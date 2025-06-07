import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objs as go
import random

# Initialize the Dash app
app = dash.Dash(__name__)

# Initial categories for the bar chart
categories = ['Apples', 'Bananas', 'Cherries']

# Layout
app.layout = html.Div([
    html.H2("Live Updating Bar Chart"),
    dcc.Graph(id='live-bar-chart'),
    dcc.Interval(
        id='interval-component',
        interval=1000,  # in milliseconds
        n_intervals=0   # start at zero
    )
])

# Callback to update the chart
@app.callback(
    Output('live-bar-chart', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_bar_chart(n):
    # Simulate new data
    values = [random.randint(0, 10) for _ in categories]

    # Create the bar chart
    fig = go.Figure(data=[go.Bar(x=categories, y=values)])
    fig.update_layout(
        yaxis=dict(range=[0, 10]),
        transition_duration=500
    )
    return fig

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
