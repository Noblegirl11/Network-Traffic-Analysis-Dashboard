import pandas as pd
import dash
from dash import dcc, html, dash_table
import plotly.express as px

app = dash.Dash(__name__)

def load_data():
    try:
        df = pd.read_csv("vpn_attack_logs1.csv")
        return df
    except:
        return pd.DataFrame(columns=["Source IP", "Destination IP", "Protocol", "VPN Status", "Attack Warning"])

app.layout = html.Div([
    html.H1("🔍 Network Traffic Analysis Dashboard", style={'textAlign': 'center'}),
    dcc.Interval(id='interval-component', interval=5000, n_intervals=0),
    html.Div([
        html.H3("📌 Captured Packets"),
        dash_table.DataTable(id='packet-table', page_size=10, style_table={'overflowX': 'auto'})
    ]),
    html.Div([
        html.H3("📊 Attack Statistics"),
        dcc.Graph(id='attack-graph')
    ])
])

@app.callback(
    [dash.dependencies.Output('packet-table', 'data'),
     dash.dependencies.Output('attack-graph', 'figure')],
    [dash.dependencies.Input('interval-component', 'n_intervals')]
)
def update_data(n):
    df = load_data()
    attack_counts = df["Attack Warning"].value_counts()
    attack_graph = px.bar(attack_counts, x=attack_counts.index, y=attack_counts.values, title="Detected Attacks")
    return df.to_dict('records'), attack_graph

if __name__ == '__main__':
    app.run_server(debug=True)
