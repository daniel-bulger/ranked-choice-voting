import functools
import os
from flask import Flask, abort, current_app, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pyrankvote
from pyrankvote import Candidate, Ballot
import condorcet
from flask_discord import DiscordOAuth2Session
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from google.cloud import secretmanager


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
    username = db.Column(db.String(80), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)


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
    return User.query.filter_by(username=discord.fetch_user().username).first()

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
        existing_user = User.query.filter_by(username=user.username).first()
        if not existing_user:
            print(user.id)
            new_user = User(username=user.username, is_admin=user.username=='dpbulger')
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


def get_instant_runoff_winner():
    # Retrieve all the movies
    movies = Movie.query.order_by(Movie.id).filter_by(is_approved=True).all()

    # Create a Candidate object for each movie
    candidates = [Candidate(movie.title) for movie in movies]
    id_to_candidate_index = {}
    for i,movie in enumerate(movies):
        id_to_candidate_index[movie.id] = i

    # Retrieve all the user preferences
    all_preferences = Preference.query.order_by(Preference.order).all()

    # Group preferences by user_id
    user_preferences = {}
    for preference in all_preferences:
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

def find_condorcet_winners():
    # Retrieve all the movies
    movies = Movie.query.order_by(Movie.id).filter_by(is_approved=True).all()

    # Create a Candidate object for each movie
    candidates = [movie.title for movie in movies]
    id_to_candidate_index = {}
    for i,movie in enumerate(movies):
        id_to_candidate_index[movie.id] = i

    # Retrieve all the user preferences
    all_preferences = Preference.query.order_by(Preference.order).all()

    # Group preferences by user_id
    user_preferences = {}
    for preference in all_preferences:
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



@app.route('/results')
@requires_authorization
def results():
    condorcet_winners = find_condorcet_winners()
    if condorcet_winners:
        winners = condorcet_winners
    else:
        # Run the Instant Runoff Voting (IRV) election
        election_result = get_instant_runoff_winner()
        # Get the winner
        winners = [winner.name for winner in election_result]
        print(election_result)

    return render_template('results.html', winners=winners)

if __name__ == "__main__":
    logging.info("running")
    app.run()