#!/usr/bin/python3

from datetime import datetime

import calendar

import sqlite3

import os

months = ['January', 'February', 'March', 'April', 'May',
              'June', 'July', 'August', 'September', 'October',
              'November', 'December']

calendar_db = 'PythonicTeamsCalendarTest/calendar.db'

def initialise_calendar():
    calendar_db = 'PythonicTeamsCalendarTest/calendar.db'
    if not os.path.exists(calendar_db):
        sqlite3.connect(calendar_db).close()
        try:
            conn = sqlite3.connect(calendar_db)
            c = conn.cursor()
            now = datetime.utcnow()
            c.execute(f'''CREATE TABLE calendar(title VARCHAR(255), event TEXT, date_created DATETIME, day INTEGER, month VARCHAR(25), year INTEGER)''')
            conn.commit()
            conn.close()
            return
        except sqlite3.OperationalError as e:
            print(e)
            return
    return
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

def add_new_event(Title, Event, Day, Month, Year):
    try:
        conn = sqlite3.connect(calendar_db)
        c = conn.cursor()
        now = datetime.utcnow()
        c.execute('''INSERT INTO calendar(title, event, date_created, day, month, year) VALUES(?,?,?,?,?,?)''', (Title, Event, now, Day, Month, Year))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(e)

#function to retrieve all events in a given month.
#if not month return empty dict
#else return a dict with key "date": value "Event"
def retrieve_all_events_in_month(Month):
    conn = None
    try:
        conn = sqlite3.connect(calendar_db)
        c = conn.cursor()
        c.execute('''SELECT * FROM calendar WHERE month = :month''')
        calendar_events_list = list(c.fetchall())
        conn.close()
        return calendar_events
    except:
        pass