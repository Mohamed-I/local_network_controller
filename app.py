from flask import Flask, Blueprint, render_template

app = Flask(__name__)

site = Blueprint('site', __name__, template_folder='templates')

# Sample data for demonstration
activity_list = [
    {"id": 1, "name": "Activity 1", "description": "Description of Activity 1"},
    {"id": 2, "name": "Activity 2", "description": "Description of Activity 2"},
    {"id": 3, "name": "Activity 3", "description": "Description of Activity 3"},
]

logs = [
    {"id": 1, "timestamp": "2024-06-22 10:00:00", "message": "Log message 1"},
    {"id": 2, "timestamp": "2024-06-22 11:00:00", "message": "Log message 2"},
    {"id": 3, "timestamp": "2024-06-22 12:00:00", "message": "Log message 3"},
]


@app.route('/')
def index():
    page_title = "Monitor devices activities"
    table_data = [
        {"col1": "Row 1 Col 1", "col2": "Row 1 Col 2",
            "col3": "Row 1 Col 3", "col4": "Row 1 Col 4"},
        {"col1": "Row 2 Col 1", "col2": "Row 2 Col 2",
            "col3": "Row 2 Col 3", "col4": "Row 2 Col 4"},
        {"col1": "Row 3 Col 1", "col2": "Row 3 Col 2",
            "col3": "Row 3 Col 3", "col4": "Row 3 Col 4"},
    ]
    return render_template('index.html', title=page_title, table_data=table_data)


@app.route('/activities')
def activities():
    return render_template('activities.html', activities=activity_list)


@app.route('/details/<int:activity_id>')
def details(activity_id):
    # Example: retrieve details for activity_id
    activity = next(
        (act for act in activity_list if act['id'] == activity_id), None)
    if activity:
        return render_template('details.html', activity=activity, logs=logs)
    else:
        return "Activity not found"


if __name__ == '__main__':
    app.run(debug=True)
