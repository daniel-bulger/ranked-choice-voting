import functools
from datetime import datetime, time, timedelta
import logging
import pytz
import os
from dotenv import load_dotenv
import time
import random

from flask import Flask, abort, current_app, render_template, request, redirect, url_for, flash, jsonify
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
from wtforms import SelectField, SubmitField, StringField
from wtforms.fields import DateField
from wtforms.validators import DataRequired, Length
from flask_bootstrap import Bootstrap4

from better_instant_runoff import run_instant_runoff_election

load_dotenv()  # Load environment variables from .env file

def access_secret_version(secret_id, version_id="latest"):
    project_id = "722181616115"
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")

# GCP project in which to store secrets in Secret Manager.

app = Flask(__name__)
bootstrap = Bootstrap4(app)
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

class WatchedMovie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    watched_date = db.Column(db.Date, nullable=False)
 
# db.create_all() # Can be uncommented now if desired, though migrations handle it.
db.create_all() # Or simply remove the comment

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
admin.add_view(UserModelView(WatchedMovie, db.session))

@app.route('/approve_movies')
@requires_authorization
def approve_movies():
    if not get_current_user().is_admin:
        abort(403)  # Forbidden
    unapproved_movies = Movie.query.filter_by(is_approved=False).all()
    return render_template('approve_movies.html', unapproved_movies=unapproved_movies, current_user=get_current_user())


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

@app.route('/reject_movie/<int:movie_id>', methods=['POST'])
@requires_authorization
def reject_movie(movie_id):
    if not get_current_user().is_admin:
        abort(403)  # Forbidden
    movie = Movie.query.get(movie_id)
    if movie:
        # Check if it has any votes before deleting? (Optional safety)
        # Preference.query.filter_by(movie_id=movie_id).delete()
        db.session.delete(movie)
        db.session.commit()
        flash(f'Movie proposal "{movie.title}" rejected and removed.', 'success')
    else:
        flash(f'Movie with ID {movie_id} not found.', 'error')
    return redirect(url_for('approve_movies'))

# New route for requesting movies
class RequestMovieForm(FlaskForm):
    title = StringField('Movie Title', validators=[DataRequired(), Length(min=1, max=200)])
    submit = SubmitField('Request Movie')

@app.route('/request_movie', methods=['GET', 'POST'])
@requires_authorization
def request_movie():
    form = RequestMovieForm()
    if form.validate_on_submit():
        title = form.title.data
        # Check if movie already exists (approved or not)
        existing_movie = Movie.query.filter(Movie.title.ilike(title)).first()
        if existing_movie:
            flash(f'Movie "{existing_movie.title}" already exists in the list (approved or pending).', category='warning')
        else:
            new_movie = Movie(title=title, is_approved=False)
            db.session.add(new_movie)
            db.session.commit()
            flash(f'Movie "{title}" proposed for approval.', category='success')
            return redirect(url_for('index')) # Redirect to index after successful request
        # If movie exists or other validation error, re-render the form
    # Pass current_user for the base template
    return render_template('request_movie.html', form=form, current_user=get_current_user())

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


    # Sort the unsorted movies based on what would be winning if everyone's votes counted.
    preferences = Preference.query.all()
    ranked_movie_ids = get_instant_runoff_winner_ids(preferences)[1]
    # Add any movies that are not in the user's preferences to the end of the list
    unsorted_movies = [movie for movie in all_movies if movie.id not in sorted_movie_ids and movie.id not in ranked_movie_ids]
    ranked_movies = []
    for movie_id in ranked_movie_ids:
        if movie_id in sorted_movie_ids: continue
        for movie in all_movies:
            if movie.id == movie_id:
                ranked_movies.append(movie)

    return render_template('index.html', movies=sorted_movies, unordered_movies = ranked_movies + unsorted_movies, current_user=get_current_user())

@app.route('/autosave_preferences', methods=['POST'])
@requires_authorization
def autosave_preferences():
    user = get_current_user()
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 401

    data = request.get_json()
    if not data or 'movie_ids' not in data: # Expecting 'movie_ids' key
        return jsonify({'status': 'error', 'message': 'Missing or invalid data'}), 400

    submitted_movie_ids = set(int(id_str) for id_str in data['movie_ids']) # Use a set for faster lookups
    submitted_movie_id_list = [int(id_str) for id_str in data['movie_ids']] # Keep ordered list
    
    try:
        # Fetch ALL existing preferences for the user
        existing_prefs = Preference.query.filter_by(user_id=user.id).all()
        existing_prefs_map = {pref.movie_id: pref for pref in existing_prefs}
        existing_movie_ids = set(existing_prefs_map.keys())

        # --- Update and Create --- 
        for index, movie_id in enumerate(submitted_movie_id_list):
            if movie_id in existing_prefs_map:
                # Update existing preference order if changed
                preference = existing_prefs_map[movie_id]
                if preference.order != index:
                    preference.order = index
                    db.session.add(preference) 
            else:
                # Create new preference if it was added (should exist in Movie table)
                movie_exists = Movie.query.get(movie_id)
                if movie_exists:
                    new_preference = Preference(user_id=user.id, movie_id=movie_id, order=index)
                    print(f"Autosave: Creating new pref for movie {movie_id} at index {index}")
                    db.session.add(new_preference)
                else:
                     print(f"Autosave: Movie ID {movie_id} not found, skipping preference creation.")

        # --- Delete Removed Preferences --- 
        ids_to_delete = existing_movie_ids - submitted_movie_ids
        if ids_to_delete:
            print(f"Autosave: Deleting preferences for movie IDs: {ids_to_delete}")
            Preference.query.filter(
                Preference.user_id == user.id,
                Preference.movie_id.in_(ids_to_delete)
            ).delete(synchronize_session=False) # Use False for bulk delete

        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Preferences saved'})
    except Exception as e:
        db.session.rollback() # Rollback on error
        print(f"Error during autosave: {e}") # Log the error server-side
        return jsonify({'status': 'error', 'message': 'Server error during save'}), 500

def get_instant_runoff_winner_ids(preferences, current_user_id = 0):
    # If there are no preferences, return an empty result immediately
    if not preferences:
        return ([], [], [])

    ranking_per_voter = []
    # Group preferences by user_id
    preferences_by_user = {}
    for preference in preferences:
        if preference.user_id not in preferences_by_user:
            preferences_by_user[preference.user_id] = {}
        preferences_by_user[preference.user_id][preference.order]=preference.movie_id
    user_preference_list = []
    # Put the current user's preferences first since the IRV algo will return data about who the first voter voted for.
    for user_id, user_preferences in preferences_by_user.items():
        if user_id == current_user_id:
            user_preference_list.append([candidate for order,candidate in sorted(user_preferences.items())])
    for user_id, user_preferences in preferences_by_user.items():
        if user_id != current_user_id:
            user_preference_list.append([candidate for order,candidate in sorted(user_preferences.items())])

    # Run the Instant Runoff Voting (IRV) election
    return run_instant_runoff_election(user_preference_list)

def get_movie_name(id, id_to_name):
    return id_to_name.get(id,"Unknown movie with id {0}".format(x))

def get_instant_runoff_winners(preferences,current_user_id = 0):
    election_result = get_instant_runoff_winner_ids(preferences,current_user_id)
    # Retrieve all the movies
    movies = Movie.query.order_by(Movie.id).filter_by(is_approved=True).all()
    # Create a Candidate object for each movie
    id_to_name = {}
    for movie in movies:
        id_to_name[movie.id] = movie.title

    print(election_result)
    ranked_names = ([get_movie_name(x,id_to_name) for x in election_result[1]],[{get_movie_name(k,id_to_name):v for k,v in d.items()} for d in election_result[0]],[[get_movie_name(x,id_to_name) for x in y] for y in election_result[2]])
    return ranked_names

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
            user_preferences[preference.user_id] = {}
        user_preferences[preference.user_id][preference.order] = candidates[id_to_candidate_index[preference.movie_id]]

    # Transform the data to work with 

    # Create a ballot for each user using their preferences
    total_movies = len(movies)
    votes = []
    for prefs in user_preferences.values():
        next_prefs = {}
        for movie in movies:
            next_prefs[movie.title] = total_movies
        for order, movie_title in prefs.items():
            next_prefs[movie_title] = order
        votes.append(next_prefs)

    evaluator = condorcet.CondorcetEvaluator(candidates=candidates, votes=votes)
    winners, rest_of_table = evaluator.get_n_winners(3)
    print(winners,rest_of_table)
    return winners


def get_interested_voters():
    max_retries = 3
    initial_delay = 1  # seconds
    
    for attempt in range(max_retries):
        try:
            # Define the URL for the API call
            get_events_url = f"https://discord.com/api/guilds/226530292393836544/scheduled-events"
            # Define the headers for the API call
            headers = {
                'Authorization': f'Bot {os.getenv("DISCORD_BOT_TOKEN")}',
            }
            # Make the API call
            events_response = requests.get(get_events_url, headers=headers, timeout=10) # Added timeout
            events_response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            
            next_movie_night = None
            # Check if response is valid JSON and is a list
            try:
                events_data = events_response.json()
                if not isinstance(events_data, list):
                    print(f"Unexpected Discord events response format: {events_data}")
                    events_data = [] # Treat as empty if not a list
            except requests.exceptions.JSONDecodeError:
                print(f"Failed to decode Discord events JSON response: {events_response.text}")
                events_data = []

            for event in events_data:
                # Basic check for dictionary structure and necessary keys
                if isinstance(event, dict) and 'name' in event and 'scheduled_start_time' in event:
                    if "movie" in event['name'].lower(): # Check lower case
                        if not next_movie_night or event['scheduled_start_time'] < next_movie_night['scheduled_start_time']:
                            next_movie_night = event
                else:
                    print(f"Skipping malformed event data: {event}")

            if next_movie_night is None:
                print("No relevant 'movie' event found in Discord scheduled events.")
                return [] # Return empty list if no event found, not None
            
            get_users_url = f"https://discord.com/api/guilds/226530292393836544/scheduled-events/{next_movie_night['id']}/users"
            get_users_response = requests.get(get_users_url, headers=headers, timeout=10) # Added timeout
            get_users_response.raise_for_status()
            
            # Check if response is valid JSON and is a list
            try:
                users_data = get_users_response.json()
                if not isinstance(users_data, list):
                    print(f"Unexpected Discord users response format: {users_data}")
                    return [] # Return empty list if format is wrong
            except requests.exceptions.JSONDecodeError:
                 print(f"Failed to decode Discord users JSON response: {get_users_response.text}")
                 return [] # Return empty list on decode error

            # Extract IDs, checking structure
            interested_ids = []
            for user_entry in users_data:
                if isinstance(user_entry, dict) and 'user' in user_entry and isinstance(user_entry['user'], dict) and 'id' in user_entry['user']:
                    interested_ids.append(user_entry['user']['id'])
                else:
                    print(f"Skipping malformed user data: {user_entry}")
            
            return interested_ids # Success!
            
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1} failed: Error during Discord API request: {e}")
            if attempt == max_retries - 1:
                print("Max retries reached. Failing operation.")
                return None # Return None only after all retries fail
            
            # Calculate delay with exponential backoff and jitter
            delay = (initial_delay * (2 ** attempt)) + random.uniform(0, 1)
            print(f"Retrying in {delay:.2f} seconds...")
            time.sleep(delay)
            
    return None # Should not be reached if loop completes, but acts as final fallback

@app.route('/results')
@requires_authorization
def results():
    # Update whose vote should count. This involves Discord API calls.
    raw_interested_ids = get_interested_voters()
    
    if raw_interested_ids is None:
        # Error fetching from Discord, fall back to counting all votes
        print("Error fetching interested voters from Discord. Counting all votes as a fallback.")
        for user in User.query.all():
            user.vote_counts = True
        interested_ids = None # Explicitly set to None for the later check (though not strictly necessary now)
    else:
        # Successfully fetched IDs, process them
        interested_ids = [int(id) for id in raw_interested_ids]
        print(f"Interested Discord IDs: {interested_ids}")
        # Mark users based on fetched IDs
        all_users = User.query.all()            
        for user in all_users:
            if user.discord_id in interested_ids:
                user.vote_counts = True
                print(f"User {user.username} ({user.discord_id}) is interested.")
            else:
                user.vote_counts = False
                
    # This check might be redundant now but doesn't hurt
    # if interested_ids is None: 
    #     print("No upcoming movie night or error fetching. Counting all votes.")
    #     for user in User.query.all():
    #         user.vote_counts = True
            
    db.session.commit()

    # Only count the preferences for voters whose vote_counts is True
    preferences = Preference.query.join(User).filter(User.vote_counts==True).all()
    if not preferences:
        return render_template('no_results.html', current_user=get_current_user())
    # Something seems wrong with condorcet so commenting this out for now.
    # condorcet_winners = find_condorcet_winners(preferences)
    # if condorcet_winners:
    #     winners = condorcet_winners
    # Run the custom Instant Runoff Voting (IRV) election
    winners,votes,my_votes = get_instant_runoff_winners(preferences,get_current_user().id)
    if not get_current_user().vote_counts:
        for i in range(len(my_votes)):
            my_votes[i] = []
    print(winners)
    winners = winners[:5]

    return render_template('results.html', winners=winners, votes=votes, my_votes=my_votes, current_user=get_current_user())

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
        watched_date = DateField('Watched Date', format='%Y-%m-%d', validators=[DataRequired()], default=datetime.utcnow)
        submit = SubmitField('Mark as Watched')
    form = ClearVotesForm()

    # Handle the POST request with form data
    if form.validate_on_submit():
        movie_id = form.movie.data
        watched_date = form.watched_date.data
        movie = Movie.query.get(movie_id)

        if movie:
            # Create WatchedMovie record
            watched_movie = WatchedMovie(title=movie.title, watched_date=watched_date)
            db.session.add(watched_movie)

            # Delete all votes related to this movie
            Preference.query.filter_by(movie_id=movie_id).delete()

            # Delete the movie itself
            db.session.delete(movie)

            # Commit all changes
            db.session.commit()
            flash(f'"{movie.title}" marked as watched on {watched_date.strftime("%Y-%m-%d")} and removed from voting list.', "success")
        else:
            flash(f'Movie with ID {movie_id} not found.', 'error')
            
        return redirect(url_for('index'))

    # Handle the GET request to display the form
    return render_template('clear_votes.html', form=form, current_user=get_current_user())

@app.route('/create-event', methods=['GET', 'POST'])
@requires_authorization
def create_event():
    if not get_current_user().is_admin:
        abort(403)  # Forbidden

    if request.method == 'POST':
        create_movie_event()
        return 'Event created successfully'
    else:
        return render_template('create_event.html', current_user=get_current_user())

@app.route('/history')
@requires_authorization
def history():
    watched_movies = WatchedMovie.query.order_by(WatchedMovie.watched_date.desc()).all()
    return render_template('history.html', watched_movies=watched_movies, current_user=get_current_user())

if __name__ == "__main__":
    print("running")
    logging.info("running")
    context = ('localhost.cert', 'localhost.key')
    app.run(ssl_context=context)
