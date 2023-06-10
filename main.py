import functools
from datetime import datetime, time, timedelta
import logging
import pytz
import os
from flask import Flask, abort, current_app, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import login_user, logout_user, current_user
import requests
from werkzeug.security import generate_password_hash, check_password_hash
import pyrankvote
from pyrankvote import Candidate, Ballot
import condorcet
from flask_discord import DiscordOAuth2Session
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from google.cloud import secretmanager
from flask_wtf import FlaskForm
from wtforms import SelectField, SubmitField
from wtforms.validators import DataRequired


def access_secret_version(secret_id, version_id="latest"):
    project_id = "722181616115"
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")

# GCP project in which to store secrets in Secret Manager.

app = Flask(__name__)
app.app_context().push()
if not os.environ.get('SECRET_KEY'):
    os.environ['SECRET_KEY'] = access_secret_version('ranked-choice-flask-app-secret-key')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

if not os.environ.get('DISCORD_CLIENT_ID'):
    os.environ['DISCORD_CLIENT_ID'] = access_secret_version('ranked-choice-discord-client-id')
app.config["DISCORD_CLIENT_ID"] = os.environ.get('DISCORD_CLIENT_ID')
if not os.environ.get('DISCORD_CLIENT_SECRET'):
    os.environ['DISCORD_CLIENT_SECRET'] = access_secret_version('ranked-choice-discord-client-secret')
if not os.environ.get('DISCORD_BOT_TOKEN'):
    os.environ['DISCORD_BOT_TOKEN'] = access_secret_version('ranked-choice-discord-bot-token')
app.config["DISCORD_CLIENT_SECRET"] = os.environ.get('DISCORD_CLIENT_SECRET')
app.config["DISCORD_REDIRECT_URI"] = os.environ.get('DISCORD_REDIRECT_URI')
app.config["DISCORD_SCOPE"] = ["identify","guilds"]

discord = DiscordOAuth2Session(app)

# Replace the SQLite database URI with your PostgreSQL database URI
if os.environ.get('CLOUD_SQL_CONNECTION_NAME'):
    db_user = os.environ.get('CLOUD_SQL_USERNAME')
    db_pass = access_secret_version('ranked-choice-db-password')
    db_name = os.environ.get('CLOUD_SQL_DATABASE_NAME')
    db_connection_name = os.environ.get('CLOUD_SQL_CONNECTION_NAME')
    db_uri = f'postgresql://{db_user}:{db_pass}@/{db_name}?host=/cloudsql/{db_connection_name}'
else:
    db_uri = f'sqlite:///movies.db'
app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False



db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.Integer, unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    vote_counts = db.Column(db.Boolean, nullable=False, default=True)


class Movie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)


class Preference(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=False)
    movie_id = db.Column(db.BigInteger, db.ForeignKey('movie.id'), nullable=False)
    order = db.Column(db.BigInteger, nullable=False)
 
db.create_all()

def requires_authorization(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not current_app.discord.authorized:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper

def get_current_user():
    return User.query.filter_by(discord_id=discord.fetch_user().id).first()

@app.before_request
def redirect_to_primary_domain():
    primary_domain = os.environ.get('PRIMARY_DOMAIN')
    if not primary_domain:
        return
    current_domain = request.host

    if current_domain != primary_domain:
        url = request.url.replace(current_domain, primary_domain)
        return redirect(url, code=301)

@app.route('/login')
def login():
    return discord.create_session(scope=['identify','guilds'])

@app.route('/callback')
def callback():
    discord.callback()
    user = discord.fetch_user()
    # Check if the user is a member of your Discord server
    # Replace 'your_guild_id' with the ID of your Discord server
    guilds = discord.fetch_guilds()
    print(["%s %s"%(guild.id, guild.name) for guild in guilds])
    if any(guild.id == 226530292393836544 for guild in guilds):
        existing_user = User.query.filter_by(discord_id=user.id).first()
        if not existing_user:
            existing_user = User.query.filter_by(username=user.username).first()
        if not existing_user:
            print(user.id)
            new_user = User(discord_id=user.id, username=user.username, is_admin=user.id==267396214939451396)
            db.session.add(new_user)
            db.session.commit()
        return redirect(url_for('index'))
    else:
        return "You must be a member of the Discord server to use this app.", 403

@app.route('/logout')
@requires_authorization
def logout():
    discord.revoke()
    return redirect(url_for('index'))

class UserModelView(ModelView):
    column_exclude_list = ['password']
    form_excluded_columns = ['password']

    def is_accessible(self):
        current_user = get_current_user()
        return current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))

admin = Admin(app, name='Ranked Choice Voting', template_mode='bootstrap3')
admin.add_view(UserModelView(User, db.session))
admin.add_view(UserModelView(Movie, db.session))
class PreferenceModelView(UserModelView):
    column_list = ['id', 'user_id', 'movie_id', 'order']
admin.add_view(PreferenceModelView(Preference, db.session))

@app.route('/approve_movies')
@requires_authorization
def approve_movies():
    if not get_current_user().is_admin:
        abort(403)  # Forbidden
    unapproved_movies = Movie.query.filter_by(is_approved=False).all()
    return render_template('approve_movies.html', unapproved_movies=unapproved_movies)


@app.route('/approve_movie/<int:movie_id>', methods=['POST'])
@requires_authorization
def approve_movie(movie_id):
    if not get_current_user().is_admin:
        abort(403)  # Forbidden
    movie = Movie.query.get(movie_id)
    if movie:
        movie.is_approved = True
        db.session.commit()
    return redirect(url_for('approve_movies'))


@app.route('/add_movie', methods=['POST'])
@requires_authorization
def add_movie():
    title = request.form['title']
    movie = Movie.query.filter_by(title=title).first()
    if movie:
        flash('Movie already exists.', category='error')
    elif len(title) < 1:
        flash('Movie title is too short.', category='error')
    else:
        new_movie = Movie(title=title, is_approved=False)
        db.session.add(new_movie)
        db.session.commit()
        flash('Movie proposed for approval.', category='success')
    return redirect(url_for('index'))


@app.route('/', methods=['GET'])
@requires_authorization
def index():
    # Get the user's preferences
    user_preferences = Preference.query.filter_by(user_id=get_current_user().id).order_by(Preference.order).all()
    print(user_preferences)

    # Create a list of movie IDs sorted by the user's preferences
    sorted_movie_ids = [pref.movie_id for pref in user_preferences]

    # Get all the movies and create a dictionary with their IDs as keys
    all_movies = Movie.query.filter_by(is_approved=True).all()

    movies_dict = {movie.id: movie for movie in all_movies}

    # Sort the movies based on the user's preferences
    sorted_movies = [movies_dict[movie_id] for movie_id in sorted_movie_ids if movie_id in movies_dict]
    print(sorted_movies)


    # Add any movies that are not in the user's preferences to the end of the list
    unsorted_movies = [movie for movie in all_movies if movie.id not in sorted_movie_ids]

    return render_template('index.html', movies=sorted_movies, unordered_movies = unsorted_movies,username=get_current_user().username)

@app.route('/update_preferences', methods=['POST'])
@requires_authorization
def update_preferences():
    movie_order = request.form.getlist('movie[]')
    unordered_movies = request.form.getlist('unordered_movie[]')
    print(movie_order)

    for index, movie_id in enumerate(movie_order):
        preference = Preference.query.filter_by(user_id=get_current_user().id, movie_id=movie_id).first()
        
        if preference:
            preference.order = index
            db.session.add(preference)  # Add the updated preference object to the session
        else:
            new_preference = Preference(user_id=get_current_user().id, movie_id=movie_id, order=index)
            db.session.add(new_preference)

    # Delete preferences for unordered movies
    for unordered_movie_id in unordered_movies:
        unordered_movie = Movie.query.get(unordered_movie_id)
        if unordered_movie:
            preference = Preference.query.filter_by(user_id=get_current_user().id, movie_id=unordered_movie_id).first()
            if preference:
                db.session.delete(preference)

    db.session.commit()
    return redirect('/')


def get_instant_runoff_winner(preferences):
    # Retrieve all the movies
    movies = Movie.query.order_by(Movie.id).filter_by(is_approved=True).all()
    # The library breaks if there's only one candidate -- return it early instead.
    if len(movies) == 1:
        return [Candidate(movies[0].title)]
    # Create a Candidate object for each movie
    candidates = [Candidate(movie.title) for movie in movies]
    id_to_candidate_index = {}
    for i,movie in enumerate(movies):
        id_to_candidate_index[movie.id] = i

    # Group preferences by user_id
    user_preferences = {}
    for preference in preferences:
        if preference.user_id not in user_preferences:
            user_preferences[preference.user_id] = []
        user_preferences[preference.user_id].append(candidates[id_to_candidate_index[preference.movie_id]])

    # Create a ballot for each user using their preferences
    ballots = [Ballot(ranked_candidates=prefs) for prefs in user_preferences.values()]

    # Run the Instant Runoff Voting (IRV) election
    election_result = pyrankvote.instant_runoff_voting(candidates, ballots)
    # Get the winner
    winners = election_result.get_winners()[:3]
    print(election_result)
    return winners

def find_condorcet_winners(preferences):
    # Retrieve all the movies
    movies = Movie.query.order_by(Movie.id).filter_by(is_approved=True).all()

    # Create a Candidate object for each movie
    candidates = [movie.title for movie in movies]
    id_to_candidate_index = {}
    for i,movie in enumerate(movies):
        id_to_candidate_index[movie.id] = i

    # Group preferences by user_id
    user_preferences = {}
    for preference in preferences:
        if preference.user_id not in user_preferences:
            user_preferences[preference.user_id] = []
        user_preferences[preference.user_id].append(candidates[id_to_candidate_index[preference.movie_id]])

    # Transform the data to work with 

    # Create a ballot for each user using their preferences
    total_movies = len(movies)
    votes = []
    for prefs in user_preferences.values():
        next_prefs = {}
        for movie in movies:
            next_prefs[movie.title] = total_movies
        for i, pref in enumerate(prefs):
            next_prefs[pref] = i
        votes.append(next_prefs)

    evaluator = condorcet.CondorcetEvaluator(candidates=candidates, votes=votes)
    winners, rest_of_table = evaluator.get_n_winners(3)
    print(winners,rest_of_table)
    return winners


def get_interested_voters():
    try:
        # Define the URL for the API call
        get_events_url = f"https://discord.com/api/guilds/226530292393836544/scheduled-events"
        # Define the headers for the API call
        headers = {
            'Authorization': f'Bot {os.getenv("DISCORD_BOT_TOKEN")}',
        }
        # Make the API call
        events_response = requests.get(get_events_url, headers=headers)
        next_movie_night = None
        for event in events_response.json():
            if "movie" in event['name'] or "Movie" in event['name']:
                if not(next_movie_night) or event['start_time'] < next_movie_night['start_time']:
                    next_movie_night = event
        if next_movie_night is None:
            return None
        get_users_url = f"https://discord.com/api/guilds/226530292393836544/scheduled-events/{next_movie_night['id']}/users"
        get_users_response = requests.get(get_users_url,headers=headers).json()
        return [user['user']['id'] for user in get_users_response]
    except Exception as e:
        print(e)
        return None

@app.route('/results')
@requires_authorization
def results():
    # Update whose vote should count.  This involves Discord API calls.
    interested_ids = [int(id) for id in get_interested_voters()]
    print(interested_ids)
    if interested_ids is None:
        print("No upcoming movie night :(.  Fall back to counting all votes.")
        for user in User.query.all():
            user.vote_counts = True
    else:
        # Mark all users who are interested as having their vote count for the next movie night.
        all_users = User.query.all()            
        for user in all_users:
            if user.discord_id in interested_ids:
                user.vote_counts = True
                print("user is interested")
            else:
                user.vote_counts = False
    db.session.commit()

    # Only count the preferences for voters who are attending the next movie night.
    preferences = Preference.query.join(User).filter(User.vote_counts==True).all()
    if not preferences:
        return render_template('no_results.html')
        winners = [preferences[0]]
    condorcet_winners = find_condorcet_winners(preferences)
    if condorcet_winners:
        winners = condorcet_winners
    else:
        # Run the Instant Runoff Voting (IRV) election
        election_result = get_instant_runoff_winner(preferences)
        # Get the winner
        winners = [winner.name for winner in election_result]
        print(election_result)

    return render_template('results.html', winners=winners)

def create_movie_event():
    # Define the event details
    name = 'Movie Night!'  # The name of the event
    description = 'Join us for a movie night!  Vote for which movie to watch at https://rankedchoice.xyz/ .  If you get a server error, try logging out at https://rankedchoice.xyz/logout .'  # The description of the event
    privacy_level = 2 # GUILD_ONLY
    entity_type = 2 # VOICE
    channel_id = 718591738989510706  # The ID of the channel where the event will take place

    # Get the next Saturday
    now = datetime.now()
    next_saturday = now + timedelta((5 - now.weekday() + 7) % 7)

    # Set the event to start at 9 PM Eastern
    eastern = pytz.timezone('US/Eastern')
    scheduled_start_time = eastern.localize(datetime.combine(next_saturday, time(21, 0)))
    scheduled_end_time = scheduled_start_time + timedelta(hours=2)  # End in 2 hours

    # Define the API endpoint
    url = f'https://discord.com/api/v9/guilds/226530292393836544/scheduled-events'

    # Define the headers
    headers = {
        'Authorization': f'Bot {os.getenv("DISCORD_BOT_TOKEN")}',
        'Content-Type': 'application/json',
    }

    # Define the payload
    payload = {
        'channel_id': channel_id,
        'name': name,
        'description': description,
        'privacy_level': privacy_level,
        'entity_type': entity_type,
        'scheduled_start_time': scheduled_start_time.isoformat(),
        'scheduled_end_time': scheduled_end_time.isoformat(),
    }

    # Make the API request
    response = requests.post(url, headers=headers, json=payload)
    print(response.json())


@app.route('/clear_votes', methods=['POST','GET'])
@requires_authorization
def clear_votes():
    if not get_current_user().is_admin:
        abort(403)  # Forbidden

    class ClearVotesForm(FlaskForm):
        movie = SelectField('Movie', choices=[(m.id, m.title) for m in Movie.query.all()], validators=[DataRequired()])
        submit = SubmitField('Clear Votes')
    form = ClearVotesForm()

    # Handle the POST request with form data
    if form.validate_on_submit():
        movie_id = form.movie.data
        movie = Movie.query.get(movie_id)

        # Delete all votes related to this movie
        Preference.query.filter_by(movie_id=movie_id).delete()
        db.session.commit()
        flash(f"All votes for {movie.title} have been removed.", "success")
        return redirect(url_for('index'))

    # Handle the GET request to display the form
    return render_template('clear_votes.html', form=form)

@app.route('/create-event', methods=['GET', 'POST'])
@requires_authorization
def create_event():
    if not get_current_user().is_admin:
        abort(403)  # Forbidden

    if request.method == 'POST':
        create_movie_event()
        return 'Event created successfully'
    else:
        return render_template('create_event.html')

if __name__ == "__main__":
    logging.info("running")
    app.run()