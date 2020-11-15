#!/usr/bin/python3
import sqlite3
import sys
import time
from tempfile import mkdtemp

from flask import Flask, render_template, request, session, url_for, redirect
from flask_session import Session
from flask_socketio import SocketIO


from tempfile import mkdtemp

from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

import helpers
from helpers import login_required, user_exists, retrieve_user_id, initialise

#configure application
app = Flask(__name__)

#ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOADED"] = True

#Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-chache, no-store, must-revalidare"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

#configuring app session to use filesystem
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

#initialising socketio
socketio = SocketIO(app)

#calling port
port = 5000

#configure db
#create users db
DB = 'users/users.db'
db = sqlite3.connect(DB).close()
#create chats db
CHATS = 'users/chats.db'
chats = sqlite3.connect(CHATS).close()
#create contacts db
CONTACTS = 'users/contacts.db'
contacts = sqlite3.connect(CONTACTS).close()


@app.route('/', methods=['GET', 'POST'])
# @login_required
def index():
    helpers.initialise()
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    else:
        fullname = request.form['fullname']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        helpers.add_user(Fullname=fullname, Username=username, Email=email, Hash=hashed_password)
        return helpers.success(title="Successfully registered!", msg=f"Successfully registered {username}", links="login", method="GET")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        username = request.form['username']
        password = request.form['password']
        if user_exists(username):
            id = retrieve_user_id(username)
            hashed_password = helpers.retrieve_user_password_hash(id)
            if check_password_hash(hashed_password, password):
                session["user_id"] = id
                session['port'] = port

        else:
            return f"User with username:{username} does not exists"
        session['username'] = username
        return redirect('/home')

#main userpage
@app.route('/home', methods=['GET', 'POST'])
@login_required
def main_page():
    username = session['username']
    try:
        notifications = (helpers.retrieve_user_notifications(Username=username))
        print('notifications: ', notifications)
        print(len(notifications))
    except:
        notifications = None
    if request.method == 'GET':
        return render_template('main_user_page.html', notifications=notifications)
    else:
        pass
#view to display notification content
@app.route('/view_notification/<int:id>', methods=['GET', 'POST'])
def view_notification(id):
    #first set the notification to seen
    if request.method == 'GET':
        username = session.get('username', None)
        helpers.set_seen(Username=username, notification_id=id)
        content = helpers.retrieve_content_of_notifications(Username=username, id=id)
        return render_template('view_notification.html', content=content, id=id)
    else:
        pass
@app.route('/accept/<int:id>', methods=['GET','POST'])
@login_required
def accept(id):
    username = session.get('username', None)
    sender = helpers.retrieve_notification_sender(Username=username, notification_id=id)
    helpers.add_to_contacts(Sender=sender, Recepient=username)
    return redirect('/home')

@app.route('/decline/<int:id>', methods=['GET','POST'])
@login_required
def decline(id):
    username = session.get('username', None)
    helpers.delete_notification(Username=username, notification_id=id)
    return redirect('/home')
#chats
@app.route('/messaging', methods=['GET', 'POST'])
@login_required
def chats():
    if request.method == 'POST':
        chats_list = helpers.retrieve_user_contact_list(Username=session.get('username', None))
        print(chats_list)
        return render_template('messaging.html', chats_list=chats_list)
    else:
        chats_list = helpers.retrieve_user_contact_list(Username=session.get('username', None))
        print(chats_list)
        return render_template('messaging.html', chats_list=chats_list)
#specific_chats
@app.route('/specific_chat/<int:id>', methods=['POST', 'GET'])
@login_required
def specific_chat(id):
    username = session.get('username', None)
    recepient = helpers.retrieve_contact_username(Username=username, id=id)
    helpers.create_new_chat_table(Sender=username, Recepeint=recepient)
    chats_history = helpers.retrieve_all_chats(Username=username, SpecificChat=recepient)
    chats_list = helpers.retrieve_user_contact_list(Username=session.get('username', None))
    #todo: create specific_chat.html
    if request.method == 'GET':
        return render_template('specific_chat.html', chats_history=chats_history, chats_list=chats_list, contact_name=recepient, sender=username, id=id, port = session.get('port', 5000))
    else:
        pass
@socketio.on('my event')
def handle_my_custom_event(json, methods=['GET', 'POST']):
    print('received my event: ' + str(json))
    socketio.emit('my response', json, callback=helpers.messageReceived)


@socketio.on('send_msg')
def handle_my_send_msg(json, methods=['GET', 'POST']):
    print('received send_msg: ' + str(json))
    socketio.emit('my response', json, callback=helpers.messageReceived)
    print('DICT JSON: ', dict(json))
    print('Str Json: ', dict(json)['message'])
    print('Str Json: ', dict(json)['user_name'])
    message = str(dict(json)['message'])
    sender = str(dict(json)['user_name'])
    recepient = str(dict(json)['recepient'])
    helpers.update_message_history(Username=sender, SpecificChat=recepient, Message=message, Sent_By=sender)
    print(f'Chat list updated for {sender}')
    print(f'Chat list updated for {recepient}')

#search users function
@app.route('/usersfound', methods=['GET', 'POST'])
def usersfound():
    if request.method == 'POST':
        user = helpers.retrieve_found_users(request.form['search'])
        if len(user) != 0:
            return render_template('usersfound.html', user=user)
        else:
            return f'<h1>No user found with username {request.form["search"]}</h1>'
    else:
        user = helpers.retrieve_found_users(request.form['search'])
        if len(user) != 0:
            return render_template('usersfound.html', user=user)
        else:
            return f'<h1>No user found with username {request.form["search"]}</h1>'
#function to send friend request
@app.route('/request_add_user/<int:id>', methods=['POST', 'GET'])
def request_add_user(id):
    if request.method == 'POST':
        title = 'Friend Request'
        message = request.form['message']
        sender = request.form['from']
        if not sender:
            sender = session.get('username',None)
        recepient_username = helpers.retrieve_user_with_id(id)
        helpers.add_notification(Username=recepient_username, title=title, message=message, sender=sender)
        return helpers.success(title="Sent Request!", msg=f'Successfully sent friend'
                                                          f' request to {recepient_username}', links='messaging', method='GET')
    else:
        return render_template('friend_request.html', id=id)
#projects
@app.route('/projects', methods=['GET', 'POST'])
@login_required
def projects():
    if request.method == 'GET':
        username = session.get('username', None)
        tasks = helpers.retrieve_projects(Username=username)
        return render_template('projects.html', tasks=tasks)
    else:
        username = session.get('username', None)
        project = request.form['content']
        helpers.add_project(Username=username, project=project)
        return redirect('/projects')
#route to handle deleting a project
@app.route('/delete/<int:id>', methods=['GET','POST'])
def delete(id):
    username = session.get('username', None)
    helpers.delete_projects(Username=username, id=id)
    return redirect('/projects')
#route to handle updating a project
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    if request.method == 'GET':
        return render_template('update_project.html', id=id)
    else:
        username = session.get('username', None)
        project_update = request.form['update_project']
        helpers.update_project(Username=username, id=id, project_update=project_update)
        return redirect('/projects')
#completed task access oute
@app.route('/completed/<int:id>', methods=['GET', 'POST'])
def completed(id):
    username = session.get('username', None)
    helpers.completed_project(Username=username, id=id)
    return redirect('/projects')
#calendar
@app.route('/calendar', methods=['GET', 'POST'])
@login_required
def calendar():
    username = session.get('username', None)
    current_month = helpers.retrieve_current_month()
    current_year = int(helpers.retrieve_current_year())
    current_month_index = helpers.retrieve_current_month_index(month=current_month) + 1
    month_calendar = helpers.retrieve_month_dates(year=current_year, month=current_month_index)
    month_events = helpers.retrieve_all_events_in_month(Username=username, Month=current_month)
    print(month_events)
    return render_template('calendar(2).html', current_month=current_month, current_year=current_year,
                           month_calendar=month_calendar, month_events=month_events)
#route to display previous month
@app.route('/prev/<string:month>', methods=['GET', 'POST'])
@login_required
def prev(month):
    username = session.get('username', None)
    prev_month, year = helpers.retrieve_previous_month(current_month=month)
    current_month_index = helpers.retrieve_current_month_index(month=prev_month) + 1
    month_calendar = helpers.retrieve_month_dates(year=year, month=current_month_index)
    month_events = helpers.retrieve_all_events_in_month(Username=username, Month=prev_month)
    return render_template('calendar(2).html', current_month=prev_month, current_year=year, go_back_to_current_date='Current Date!', month_calendar=month_calendar, month_events=month_events)
#route to display next month
@app.route('/next/<string:month>/<int:current_year>', methods=['GET', 'POST'])
@login_required
def next(month, current_year):
    username = session.get('username', None)
    next_month, year = helpers.retrieve_next_month(current_month=month, year=current_year)
    current_month_index = helpers.retrieve_current_month_index(month=next_month) + 1
    month_calendar = helpers.retrieve_month_dates(year=year, month=current_month_index)
    month_events = helpers.retrieve_all_events_in_month(Username=username, Month=next_month)
    return render_template('calendar(2).html', current_month=next_month, current_year=year, go_back_to_current_date='Current Date!', month_calendar=month_calendar, month_events=month_events)
#route to go back to current date
@app.route('/current_date', methods=['POST', 'GET'])
@login_required
def current_date():
    username = session.get('username', None)
    current_month = helpers.retrieve_current_month()
    current_year = helpers.retrieve_current_year()
    current_month_index = helpers.retrieve_current_month_index(month=current_month) + 1
    month_calendar = helpers.retrieve_month_dates(year=current_year, month=current_month_index)
    month_events = helpers.retrieve_all_events_in_month(Username=username, Month=current_month)
    return render_template('calendar(2).html', current_month=current_month, current_year=current_year, month_calendar=month_calendar, month_events=month_events)
#route to create new event in calendar
@app.route('/new_event/<int:day>/<string:month>/<int:year>', methods=['GET', 'POST'])
def new_event(day, month, year):
    if request.method == 'GET':
        return render_template('new_event.html', day=day, month=month, year=year)
    else:
        username = session.get('username', None)
        title = request.form['title']
        event = request.form['event']
        helpers.add_new_event(Username=username,Title=title, Event=event, Day=day, Month=month, Year=year)
        return redirect('/calendar')
#route to view event at a specific date
@app.route('/view_event/<int:day>/<string:month>/<int:year>', methods=['GET', 'POST'])
def view_event(day, month, year):
    username = session.get('username', None)
    events_list = helpers.retrieve_events_on_date(Username=username, Day=day, Month=month, Year=year)
    return render_template('view_event.html', events=events_list)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    session.clear()
    return redirect('/')

#working on settings
@app.route('/settings', methods=['POST', 'GET'])
@login_required
def settings():
    if request.method == 'POST':
        return redirect('/settings')
    else:
        return render_template('settings.html')

#username_change route
@app.route('/username_change', methods=['POST', 'GET'])
def username_change():
    if request.method == 'POST':
        return render_template('username_change.html')
    else:
        return render_template('username_change.html')
@app.route('/new_username_change', methods=['POST', 'GET'])
def new_username_change():
    OldUsername = request.form['OUsername']
    NewUsername = request.form['NUsername']
    if request.method == 'POST':
        helpers.change_username(old_username=OldUsername, new_username=NewUsername)
        return "<h1>Username changed!\nPlease login again.</h1>"
    else:
        return '<h1>An error occured</h1>'

#password change
@app.route('/password_change', methods=['POST', 'GET'])
def password_change():
    if request.method == 'POST':
        return render_template('password_change.html')
    else:
        return render_template('password_change.html')
@app.route('/new_password_change', methods=['POST', 'GET'])
def new_password_change():
    id = session.get("user_id", None)
    OldPassword = request.form['OPassword']
    NewPassword = request.form['NPassword']
    ConfirmPassword = request.form['CPassword']
    hashed_password = helpers.retrieve_user_password_hash(id)
    new_hashed_password = generate_password_hash(NewPassword, method='pbkdf2:sha256', salt_length=8)
    if not check_password_hash(hashed_password, OldPassword):
        return "<h1>Old Password is incorrect!</h1>"
    if NewPassword != ConfirmPassword:
        return"<h1>Passwords do not match!</h1>"
    if request.method == 'POST':
        helpers.change_password(old_password=hashed_password, new_password=new_hashed_password)
        return "<h1>Password changed!Please login again</h1>"
    else:
        return "<h1>An error occured!</h1>"
@app.route('/delete_account', methods=['POST', 'GET'])
def delete_account():
    if request.method == 'POST':
        return render_template('confirm_account_deletion.html')
    else:
        return render_template('confirm_account_deletion.html')
@app.route('/confirmed_account_deletion', methods=['POST', 'GET'])
def confirmed_account_deletion():
    if request.method == 'POST':
        helpers.confirmed_account_deletion(Username=session.get('username', None))
        return '<h1>ACCOUNT DELETED!</h1>'
    else:
        return '<h1>AN ERROR OCCURED</h1>'
if __name__ == '__main__':
    # app.run(host='192.168.1.12', port=8082, debug=True, threaded=True)
    socketio.run(app, host='192.168.1.12', port=8082, debug=True)