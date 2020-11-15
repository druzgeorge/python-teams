import sqlite3
import os

#create users_db if not exists
from functools import wraps

from flask import session, redirect, render_template

import threading

from datetime import datetime

DB = 'users/users.db'

def initialise():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(
        '''CREATE TABLE IF NOT EXISTS users(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, fullname VARCHAR(255) NOT NULL, username VARCHAR(20) NOT NULL, email VARCHAR(100) NOT NULL, hash BINARY(255) NOT NULL)''')
    conn.commit()
    conn.close()
    return
def create_users_db(DB):
    if not os.path.exists(DB):
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, fullname VARCHAR(255) NOT NULL, username VARCHAR(20) NOT NULL, email VARCHAR(100) NOT NULL, hash BINARY(255) NOT NULL)''')
        conn.commit()
        conn.close()
        return
    return


#add user  to users/users.db file
#todo: find  how cs50 stored password hash in their database!
def add_user(Fullname, Username, Email, Hash):
    # todo: make username distinct
    conn = None
    create_calendar_thread = threading.Thread(target=create_user_calender, args=(Username,))
    create_notifications_thread = threading.Thread(target=create_user_notifications, args=(Username,))
    create_user_contacts_thread = threading.Thread(target=create_user_contacts, args=(Username,))
    create_user_projects_table_thread = threading.Thread(target=create_user_projects_table, args=(Username,))
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('''INSERT INTO users(fullname, username, email, hash) VALUES(?,?,?,?)''', (Fullname, Username, Email, Hash))
        conn.commit()
        conn.close()
        create_calendar_thread.start()
        create_notifications_thread.start()
        create_user_contacts_thread.start()
        create_user_projects_table_thread.start()
    except sqlite3.OperationalError as e:
        print(e)

#function to create user calendar db
def create_user_calender(Username):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        #todo: in calendar layout prompt user that title can contain only 255 characters and also that it cannot be null
        c.execute(f'''CREATE TABLE IF NOT EXISTS {Username}_calendar(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, title VARCHAR(255) NOT NULL, event TEXT NOT NULL, date_created DATETIME, day INTEGER, month VARCHAR(25), year INTEGER)''')
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)

#function to create user notifications db
def create_user_notifications(Username):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        #todo: when displaying notifications, slice the string to [:12] if it is that long and append ... so it will be it's title and when clicked on display text
        #creating a boolean bit column(seen)
        # 1 for false 0 for true.This is to determine if the user has viewed this notification
        c.execute(f'''CREATE TABLE IF NOT EXISTS {Username}_notifications(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, title VARCHAR(255) NOT NULL, content TEXT NOT NULL, seen INTEGER NOT NULL DEFAULT 0, sent_by VARCHAR(20), date_sent DATETIME)''')
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)
#function to instantiate the contacts db
contacts_db = 'users/contacts.db'
def create_user_contacts(Username):
    conn = None
    try:
        conn = sqlite3.connect(contacts_db)
        c = conn.cursor()
        c.execute(f'''CREATE TABLE IF NOT EXISTS {Username}_contacts(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, fullname VARCHAR(255) NOT NULL, username VARCHAR(20) NOT NULL, email VARCHAR(100) NOT NULL)''')
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)

#function to return user contact list
def retrieve_user_contact_list(Username):
    conn = None
    try:
        conn = sqlite3.connect(contacts_db)
        c = conn.cursor()
        c.execute(f'''SELECT * FROM {Username}_contacts''')
        contatct_list = list(c.fetchall())
        conn.close()
        return  contatct_list
    except sqlite3.OperationalError as e:
        print(e)

#function to retrieve contact info
def retrieve_user_contact_info(Username, Contact):
    conn = None
    try:
        conn = sqlite3.connect(contacts_db)
        c = conn.cursor()
        c.execute(f'''SELECT * FROM {Username}_contacts WHERE username = :contact''', (Contact,))
        contatct_info = list(c.fetchall())
        conn.close()
        return contatct_info
    except sqlite3.OperationalError as e:
        print(e)
#function to add new_chat_users to each other's contacts
def add_to_contacts(Sender, Recepient):
    conn1 = None
    conn2 = None
    conn3 = None
    try:
        # retrieve all user's info from users table
        conn1 = sqlite3.connect(DB)
        c1 = conn1.cursor()
        c1.execute('''SELECT * FROM users WHERE username = :sender''', (Sender,))
        sender_info = list(c1.fetchall())
        c1.execute('''SELECT * FROM users WHERE username = :recepient''', (Recepient,))
        recepient_info = list(c1.fetchall())
        conn1.close()
        print('SENDER INFO: ', sender_info[0][1:-1])
        print('Recepient INFO: ', recepient_info[0][1:-1])
        #insert tuple results into both recepient and sender's contacts
        #working on recepient's table first
        conn2 = sqlite3.connect(contacts_db)
        c2 = conn2.cursor()
        #get rid of the id because it will conflict  in the contacts db's id
        c2.execute(f'''INSERT INTO {Recepient}_contacts(fullname, username, email) VALUES (?,?,?)''', sender_info[0][1:-1])
        conn2.commit()
        conn2.close()
        #working on sender's table secondly
        conn3 = sqlite3.connect(contacts_db)
        c3 = conn3.cursor()
        c3.execute(f'''INSERT INTO {Sender}_contacts(fullname, username, email) VALUES (?,?,?)''', recepient_info[0][1:-1])
        conn3.commit()
        conn3.close()
    except sqlite3.OperationalError as e:
        print(e)

#function to retrieve username of users from user's contact list based on id
def retrieve_contact_username(Username, id):
    conn = None
    try:
        conn = sqlite3.connect(contacts_db)
        c = conn.cursor()
        c.execute(f'''SELECT * FROM {Username}_contacts WHERE id = :id''', (id,))
        username = str(list(c.fetchall()[0])[2])
        conn.close()
        return username
    except sqlite3.OperationalError as e:
        print(e)
#function to create user chats
chats_db = 'users/chats.db'
def create_new_chat_table(Sender, Recepeint):
    conn = None
    try:
        conn = sqlite3.connect(chats_db)
        c = conn.cursor()
        c.execute(f'''CREATE TABLE IF NOT EXISTS {Sender}_{Recepeint}_chats(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, sent_by VARCHAR(20), Message TEXT, Participation VARCHAR(10), date_sent DATETIME)''')
        conn.commit()
        c.execute(f'''CREATE TABLE IF NOT EXISTS {Recepeint}_{Sender}_chats(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, sent_by VARCHAR(20), Message TEXT, Participation VARCHAR(10), date_sent DATETIME)''')
        conn.commit()
        conn.close()
        return
    except sqlite3.OperationalError as e:
        print(e)
#function to retrieve chats
def retrieve_all_chats(Username, SpecificChat):
    chats_db_file = 'users/chats.db'
    conn = None
    try:
        conn = sqlite3.connect(chats_db_file)
        c = conn.cursor()
        c.execute(f'''SELECT * FROM {Username}_{SpecificChat}_chats ORDER BY date_sent''')
        #RETURNIN ALL CHATS BUT IF THE PARTICIPATION IF NOT SENDER MAKE THAT INDEX'S ITEM '' ORDEER BY DATE_SENT
        messages = list(c.fetchall())
        conn.close()
        return messages
    except sqlite3.OperationalError as e:
        print(e)
##function to save messages to db when sent
def update_message_history(Username, SpecificChat, Message, Sent_By):
    chats_db_file = 'users/chats.db'
    conn = None
    now = datetime.utcnow()
    try:
        conn = sqlite3.connect(chats_db_file)
        c = conn.cursor()
        c.execute(f'''INSERT INTO {Username}_{SpecificChat}_chats(sent_by, Message, date_sent) VALUES(?,?,?)''', (Sent_By,Message, now))
        c.execute(f'''INSERT INTO {SpecificChat}_{Username}_chats(sent_by, Message, date_sent) VALUES(?,?,?)''', (Sent_By, Message, now))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)
#function to confirm message received
def messageReceived(methods=['GET', 'POST']):
    print('message was received!!!')
#login_required to make sure user is logged in before accessing other pages
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

#success function to display success messages with params
def success(title="Success", msg="Success", links=None, method=None):
    return render_template("success.html", title=title, msg=msg, links=links, method=method)

#function to find out if user exists
def user_exists(Username, ):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''SELECT * FROM users WHERE username = :username ''', (Username, ))
        users_found = list(c.fetchall())
        if len(users_found) < 1:
            conn.close()
            return False
        conn.close()
        return True
    except sqlite3.OperationalError as e:
        print(e)

#function to retrieve password hash
def retrieve_user_password_hash(id):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('''SELECT * FROM users WHERE id = :id''', (id,))
        users_found = list(c.fetchall())
        if len(users_found) < 1:
            conn.close()
            return f"No user with id: {id}"
        hashed_password = users_found[0][4]
        return hashed_password
    except sqlite3.OperationalError as e:
        print(e)
#function to retrieve user id based on username
def retrieve_user_id(Username):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''SELECT * FROM users WHERE username = :username ''', (Username,))
        users_found = list(c.fetchall())
        if len(users_found) < 1:
            return "User not found error!"
        id = users_found[0][0]
        conn.close()
        return id
    except sqlite3.OperationalError as e:
        print(e)
#function to retrieve searched user
def retrieve_found_users(user):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''SELECT * FROM USERS WHERE USERNAME='{user}' ''')
        userSearchResult = list(c.fetchall())
        conn.close()
        return userSearchResult
    except sqlite3.OperationalError as e:
        print(e)

#function to add notifications to user's notification
def add_notification(Username, title, message, sender):
    conn = None
    if not title:
        title = message[:int(len(title)/2)]
    now = datetime.utcnow()
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''INSERT INTO {Username}_notifications(title, content, seen, sent_by, date_sent) VALUES(?,?,?,?,?)''', (title, message, 0, sender, now))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)
#function to set user notification to seen
def set_seen(Username, notification_id):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''UPDATE {Username}_notifications SET seen = 1 WHERE id = :id''', (notification_id,))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)
#function to retrieve content of user's notifications
def retrieve_content_of_notifications(Username, id):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''SELECT content FROM {Username}_notifications WHERE id = :id''', (id,))
        message = list(c.fetchall()[0])[0]
        conn.close()
        return message
    except sqlite3.OperationalError as e:
        print(e)
#function to retrieve user's username based on their id
def retrieve_user_with_id(id):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('''SELECT username FROM users WHERE id = :id''', (id,))
        user_username = str(c.fetchall()[0][0])
        conn.close()
        return user_username
    except sqlite3.OperationalError as e:
        print(e)

#function to retrieve user's notifications
def retrieve_user_notifications(Username):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''SELECT * FROM {Username}_notifications ORDER BY date_sent''')
        notifications = list(c.fetchall())
        conn.close()
        return notifications
    except sqlite3.OperationalError as e:
        print(e)
#function to retrieve sender of a notification
def retrieve_notification_sender(Username, notification_id):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''SELECT * FROM {Username}_notifications WHERE id = :id''', (notification_id,))
        notification_row = list(c.fetchall())
        conn.close()
        sender = str(notification_row[0][4])
        return sender
    except sqlite3.OperationalError as e:
        print(e)
#function to delete notification from user's notification db
def delete_notification(Username, notification_id):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''DELETE FROM {Username}_notifications WHERE id = :id''', (notification_id,))
        conn.commit()
        conn.close()
        return
    except sqlite3.OperationalError as e:
        print(e)
#function to create users projects table in users
def create_user_projects_table(Username):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''CREATE TABLE IF NOT EXISTS {Username}_projects(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, current_status TEXT NOT NULL DEFAULT "pending", date_completed DATETIME)''')
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)
#function to insert projects into user's projects table!
def add_project(Username,project):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''INSERT INTO {Username}_projects(project) VALUES(?)''',(project,))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)

#funtion to retrieve projects from users db
def retrieve_projects(Username):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''SELECT * FROM {Username}_projects''')
        projects = list(c.fetchall())
        conn.close()
        return projects
    except sqlite3.OperationalError as e:
        print(e)

#function to delete projects from db
def delete_projects(Username, id):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''DELETE FROM {Username}_projects WHERE id = :id''',  (id,))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)

#function to update project in db
def update_project(Username, id, project_update):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        # c.execute(f'''UPDATE {Username}_notifications SET seen = 1 WHERE id = :id''', (notification_id,))
        c.execute(f'''UPDATE {Username}_projects SET project = :project WHERE id = :id''', (project_update, id))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)
#function to mark task as completed
def completed_project(Username, id):
    conn = None
    try:
        now = datetime.utcnow()
        current_status = 'completed'
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        # c.execute(f'''CREATE TABLE IF NOT EXISTS {Username}_projects(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, current_status TEXT NOT NULL DEFAULT "pending", date_completed DATETIME)''')
        # c.execute(f'''UPDATE {Username}_projects SET current_status = :current_status AND date_completed = :date_completed WHERE id = :id''', (current_status, now, id))
        c.execute(f'''UPDATE {Username}_projects SET current_status = :current_status  WHERE id = :id''', (current_status, id))
        conn.commit()
        c.execute(f'''UPDATE {Username}_projects SET date_completed = :date_completed WHERE id = :id''', (now,id))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)

'''CALENDAR METHODS BELOW'''

import calendar

months = ['January', 'February', 'March', 'April', 'May',
              'June', 'July', 'August', 'September', 'October',
              'November', 'December']

def retrieve_current_month():
    now = datetime.utcnow()
    current_month = months[now.month - 1]
    return current_month

def retrieve_current_year():
    now = datetime.utcnow()
    current_year = now.year
    return current_year

def retrieve_previous_month(current_month):
    current_month_index = months.index(current_month)
    prev_month = months[current_month_index -1]
    if current_month == months[0]:
        year = datetime.utcnow().year - 1
    else:
        year = datetime.utcnow().year
    return prev_month, year

def retrieve_next_month(current_month, year):
    current_month_index = months.index(current_month)
    try:
        next_month = months[current_month_index + 1]
        year = year
        return next_month, year
    except IndexError:
        current_month_index = 0
        next_month = months[current_month_index]
        year = year + 1
        return  next_month, year

def retrieve_month_dates(year, month):
    month_calendar = calendar.monthcalendar(year=year, month=month)
    # month_calendar[0].pop(0)
    return month_calendar

def retrieve_current_month_index(month):
    current_month_index = int(months.index(month))
    return current_month_index

def add_new_event(Username,Title, Event, Day, Month, Year):
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        now = datetime.utcnow()
        c.execute(f'''INSERT INTO {Username}_calendar(title, event, date_created, day, month, year) VALUES(?,?,?,?,?,?)''', (Title, Event, now, Day, Month, Year))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)

# function to retrieve all events in a given month.
#if not month return empty dict
#else return a dict with key "date": value "Event"
def retrieve_all_events_in_month(Username, Month):
    conn = None
    try:
        calendar_events = {} #dict
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''SELECT * FROM {Username}_calendar WHERE month = :month''', (Month,))
        calendar_events_list = list(c.fetchall())
        conn.close()
        if calendar_events_list:
            for calendar_db_entry in calendar_events_list:
                calendar_events[calendar_db_entry[4]] = calendar_db_entry
        return calendar_events
    except sqlite3.OperationalError as e:
        print(e)

#function to return events on a specific date
def retrieve_events_on_date(Username, Day,Month,Year):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''SELECT * FROM {Username}_calendar WHERE day = :day AND month = :month AND year = :year ''', (Day,Month,Year))
        events_list = list(c.fetchall())
        conn.close()
        print('events: ', events_list)
        return events_list
    except sqlite3.OperationalError as e:
        print(e)

'''SETTINGS METHODS BELOW'''
# from werkzeug.security import check_password_hash
def change_username(old_username, new_username):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''UPDATE users SET username= :new_username WHERE username= :old_username  ''', (new_username, old_username))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)

def change_password(old_password, new_password):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''UPDATE USERS SET hash= :new_password  WHERE hash= :old_password ''', (new_password, old_password))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)

def password_exists(OldPass):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('''SELECT hash FROM USERS''')
        passwords = list(c.fetchall())
        for passwd in passwords:
            if OldPass in passwd:
                return True
            continue
        conn.close()
        return False
    except sqlite3.OperationalError as e:
        print(e)

def confirmed_account_deletion(Username):
    conn = None
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(f'''DELETE FROM users WHERE username= :username  ''', (Username,))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)