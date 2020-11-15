#!/usr/bin/python3
import sqlite3

from flask import Flask, request
from flask import render_template, redirect, url_for

import helpers

app = Flask(__name__)
helpers.initialise_calendar()
@app.route('/', methods=['GET', 'POST'])
def index():
    current_month = helpers.retrieve_current_month()
    current_year = int(helpers.retrieve_current_year())
    current_month_index = helpers.retrieve_current_month_index(month=current_month) + 1
    month_calendar = helpers.retrieve_month_dates(year=current_year, month=current_month_index)
    print(month_calendar)
    return render_template('calendar(1).html', current_month=current_month, current_year=current_year, month_calendar=month_calendar)

#route to display previous month
@app.route('/prev/<string:month>', methods=['GET', 'POST'])
def prev(month):
    prev_month, year = helpers.retrieve_previous_month(current_month=month)
    current_month_index = helpers.retrieve_current_month_index(month=prev_month) + 1
    month_calendar = helpers.retrieve_month_dates(year=year, month=current_month_index)
    return render_template('calendar(1).html', current_month=prev_month, current_year=year, go_back_to_current_date='Current Date!', month_calendar=month_calendar)
#route to display next month
@app.route('/next/<string:month>/<int:current_year>', methods=['GET', 'POST'])
def next(month, current_year):
    next_month, year = helpers.retrieve_next_month(current_month=month, year=current_year)
    current_month_index = helpers.retrieve_current_month_index(month=next_month) + 1
    month_calendar = helpers.retrieve_month_dates(year=year, month=current_month_index)
    return render_template('calendar(1).html', current_month=next_month, current_year=year, go_back_to_current_date='Current Date!', month_calendar=month_calendar)
#route to go back to current date
@app.route('/current_date', methods=['POST', 'GET'])
def current_date():
    current_month = helpers.retrieve_current_month()
    current_year = helpers.retrieve_current_year()
    current_month_index = helpers.retrieve_current_month_index(month=current_month) + 1
    month_calendar = helpers.retrieve_month_dates(year=current_year, month=current_month_index)
    return render_template('calendar(1).html', current_month=current_month, current_year=current_year, month_calendar=month_calendar)
#route to create new event in calendar
@app.route('/new_event/<int:day>/<string:month>/<int:year>', methods=['GET', 'POST'])
def new_event(day, month, year):
    if request.method == 'GET':
        return render_template('new_event.html', day=day, month=month, year=year)
    else:
        title = request.form['title']
        event = request.form['event']
        helpers.add_new_event(Title=title, Event=event, Day=day, Month=month, Year=year)
        return redirect('/current_date')
if __name__ == '__main__':
    app.run()
