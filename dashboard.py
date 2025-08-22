from __future__ import annotations
from typing import Dict, Any, List

import pandas as pd
import plotly.express as px
from dash import Dash, dcc, html, dash_table, Input, Output, State, no_update

from .config import Config
from .storage import DataStore


def build_app(store: DataStore, config: Config) -> Dash:
    # Enable robust behavior during layout/callback changes
    app = Dash(__name__, suppress_callback_exceptions=True, prevent_initial_callbacks=False)
    app.title = "DNS 2.0 - Live DNS Monitor v2"

    app.layout = html.Div([
        html.H2("DNS 2.0 - Live DNS Monitor"),
        html.Div(id='summary', style={'margin': '8px 0'}),
        dcc.Interval(id='tick', interval=config.dashboard_update_ms, n_intervals=0),

        # Charts first
        html.Div([
            dcc.Graph(id='domain-frequency'),
            dcc.Graph(id='ttl-distribution'),
            dcc.Graph(id='entropy-distribution'),
            dcc.Graph(id='anomaly-types'),
            dcc.Graph(id='reputation-status'),
            dcc.Graph(id='qtype-frequency'),
            dcc.Graph(id='srcip-frequency'),
            dcc.Graph(id='events-over-time'),
            # Hidden: keep for backward-compatibility with older client callback signatures
            dcc.Graph(id='geo-map', style={'display': 'none'}),
        ], style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr', 'gap': '16px'}),

        html.H3("Live DNS Events"),
        # Export button aligned to top-right of the table
        html.Div([
            html.Button("Export as CSV", id='btn-export-csv', n_clicks=0, title="Download recent table rows as CSV",
                        style={'padding': '6px 12px', 'cursor': 'pointer'}),
            html.Button("Export as JSON", id='btn-export-json', n_clicks=0, title="Download recent table rows as JSON",
                        style={'padding': '6px 12px', 'cursor': 'pointer', 'marginLeft': '8px'})
        ], style={'display': 'flex', 'justifyContent': 'flex-end', 'gap': '8px', 'margin': '4px 0 8px 0'}),
        dcc.Download(id="download-csv"),
        dcc.Download(id="download-json"),
        dash_table.DataTable(
            id='events-table',
            columns=[
                {"name": "Time", "id": "timestamp"},
                {"name": "Src", "id": "src_ip"},
                {"name": "Dst", "id": "dst_ip"},
                {"name": "Domain", "id": "domain"},
                {"name": "QType", "id": "qtype"},
                {"name": "IPs", "id": "ips"},
                {"name": "TTL", "id": "ttl"},
                {"name": "Types", "id": "record_types"},
                {"name": "Entropy", "id": "entropy"},
                {"name": "Reputation", "id": "umbrella_status"},
                {"name": "Categories", "id": "umbrella_categories"},
                {"name": "Anomalies", "id": "anomalies"},
            ],
            data=[],
            page_size=20,
            style_cell={
                'textAlign': 'left', 
                'fontFamily': 'monospace', 
                'whiteSpace': 'normal', 
                'height': 'auto',
                'minWidth': '80px',
                'maxWidth': '200px',
                'overflow': 'hidden',
                'textOverflow': 'ellipsis',
            },
            style_table={'overflowX': 'auto'},
            style_data_conditional=[],
        ),
        
        # Add debug-info div to prevent callback errors
        html.Div(id='debug-info', style={'display': 'none'}),
    ], style={'margin': '12px'})

    # Callbacks

    # Keep original 4-output callback signature for compatibility
    @app.callback(
        Output('events-table', 'data'),
        Output('domain-frequency', 'figure'),
        Output('ttl-distribution', 'figure'),
        Output('summary', 'children'),
        Input('tick', 'n_intervals')
    )
    def update_core(_):
        import logging
        log = logging.getLogger("dashboard")
        
        try:
            # Use configurable window for the table & core charts
            df_raw = store.recent(getattr(config, 'dashboard_recent_rows', None) or None)
            log.info(f"Dashboard callback: df_raw shape={df_raw.shape}, empty={df_raw.empty}")
        except Exception as e:
            log.error(f"Error getting data from store: {e}")
            empty_bar = px.bar(pd.DataFrame({'domain': [], 'count': []}), x='domain', y='count', title='Top Domains (recent)')
            empty_hist_ttl = px.histogram(pd.DataFrame({'ttl': []}), x='ttl', title='TTL Distribution (recent)')
            summary_children = html.Div("Error loading data.")
            return [], empty_bar, empty_hist_ttl, summary_children
        
        if not df_raw.empty:
            # Build table first, so if charts fail we still show rows
            df = df_raw.copy()
            ts_numeric = pd.to_numeric(df['timestamp'], errors='coerce')
            ts_fmt = pd.to_datetime(ts_numeric, unit='s', errors='coerce').dt.strftime('%H:%M:%S')
            df['timestamp'] = ts_fmt.fillna('')
            def fmt_list(x: Any) -> str:
                if isinstance(x, list):
                    return ','.join(map(str, x))
                if x is None or (isinstance(x, float) and pd.isna(x)):
                    return ''
                return str(x)
            for col in ['ips', 'record_types', 'umbrella_categories', 'anomalies']:
                if col in df.columns:
                    df[col] = df[col].apply(fmt_list)
            df = df.fillna('')
            table_cols = ['timestamp','src_ip','dst_ip','domain','qtype','ips','ttl','record_types','entropy','umbrella_status','umbrella_categories','anomalies']
            for c in table_cols:
                if c not in df.columns:
                    df[c] = ''
            df_table = df[table_cols]
            table_records: List[Dict[str, Any]] = []
            for _, row in df_table.iterrows():
                rec: Dict[str, Any] = {}
                for col in table_cols:
                    v = row[col]
                    rec[col] = '' if (pd.isna(v) or v is None) else str(v)
                table_records.append(rec)

            # Now compute charts robustly
            try:
                freq_df = df_raw.groupby('domain', dropna=False).size().reset_index(name='count').sort_values('count', ascending=False).head(20)
                freq_fig = px.bar(freq_df, x='domain', y='count', color='count', color_continuous_scale='Turbo', title='Top Domains (recent)')
            except Exception as e:
                log.error(f"Error building domain-frequency: {e}")
                freq_fig = px.bar(pd.DataFrame({'domain': [], 'count': []}), x='domain', y='count', title='Top Domains (recent)')
            try:
                ttl_series = pd.to_numeric(df_raw['ttl'], errors='coerce').dropna().astype(float)
                if not ttl_series.empty:
                    ttl_fig = px.histogram(ttl_series.to_frame('ttl'), x='ttl', nbins=30, title='TTL Distribution (recent)')
                else:
                    ttl_fig = px.histogram(pd.DataFrame({'ttl': []}), x='ttl', title='TTL Distribution (recent)')
                ttl_fig.update_traces(marker_color='#636EFA')
                avg_ttl = float(ttl_series.mean()) if not ttl_series.empty else None
            except Exception as e:
                log.error(f"Error building ttl-distribution: {e}")
                ttl_fig = px.histogram(pd.DataFrame({'ttl': []}), x='ttl', title='TTL Distribution (recent)')
                avg_ttl = None
            try:
                ent_series = pd.to_numeric(df_raw['entropy'], errors='coerce').dropna().astype(float)
                med_entropy = float(ent_series.median()) if not ent_series.empty else None
            except Exception as e:
                log.error(f"Error computing entropy stats: {e}")
                med_entropy = None

            log.info(f"Dashboard: returning {len(table_records)} table records")
            if table_records:
                log.debug(f"Dashboard: first record = {table_records[0]}")

            total_events = int(len(store.snapshot()))
            unique_domains = int(df_raw['domain'].nunique()) if 'domain' in df_raw.columns else 0
            try:
                rows_with_anoms = int(df_raw['anomalies'].apply(lambda x: isinstance(x, list) and len(x) > 0).sum())
            except Exception:
                rows_with_anoms = 0
            anomaly_rate = (rows_with_anoms / total_events * 100.0) if total_events else 0.0

            summary_children = html.Div([
                html.Div([html.Div("Events"), html.H4(f"{total_events}")], className='metric'),
                html.Div([html.Div("Unique Domains"), html.H4(f"{unique_domains}")], className='metric'),
                html.Div([html.Div("Rows with Anomalies"), html.H4(f"{rows_with_anoms} ({anomaly_rate:.1f}%)")], className='metric'),
                html.Div([html.Div("Avg TTL"), html.H4("-" if avg_ttl is None else f"{avg_ttl:.0f}s")], className='metric'),
                html.Div([html.Div("Median Entropy"), html.H4("-" if med_entropy is None else f"{med_entropy:.2f}")], className='metric'),
            ], style={'display': 'grid', 'gridTemplateColumns': 'repeat(5, 1fr)', 'gap': '12px'})

            return table_records, freq_fig, ttl_fig, summary_children
        else:
            log.info("Dashboard: df_raw is empty, returning empty data")
            empty_bar = px.bar(pd.DataFrame({'domain': [], 'count': []}), x='domain', y='count', title='Top Domains (recent)')
            empty_hist_ttl = px.histogram(pd.DataFrame({'ttl': []}), x='ttl', title='TTL Distribution (recent)')
            summary_children = html.Div("No data yet. Start browsing to generate DNS traffic.")
            return [], empty_bar, empty_hist_ttl, summary_children

    # Add debug-info callback to prevent errors
    @app.callback(
        Output('debug-info', 'children'),
        Input('tick', 'n_intervals')
    )
    def update_debug_info(_):
        return ""

    # Secondary callback for the rest of the figures (keep geo-map output for compatibility, hidden in UI)
    @app.callback(
        Output('entropy-distribution', 'figure'),
        Output('anomaly-types', 'figure'),
        Output('reputation-status', 'figure'),
        Output('qtype-frequency', 'figure'),
        Output('srcip-frequency', 'figure'),
        Output('events-over-time', 'figure'),
        Output('geo-map', 'figure'),
        Input('tick', 'n_intervals')
    )
    def update_more(_):
        # Use a larger window for time series to improve visibility (configurable)
        df_raw = store.recent(getattr(config, 'charts_recent_rows', None) or None)
        if not df_raw.empty:
            # Entropy distribution
            ent_series = pd.to_numeric(df_raw['entropy'], errors='coerce').dropna().astype(float)
            if not ent_series.empty:
                ent_fig = px.histogram(ent_series.to_frame('entropy'), x='entropy', nbins=30, title='Domain Entropy Distribution (recent)')
            else:
                ent_fig = px.histogram(pd.DataFrame({'entropy': []}), x='entropy', title='Domain Entropy Distribution (recent)')
            ent_fig.update_traces(marker_color='#EF553B')

            # Anomaly type counts (color by count)
            def to_list(x: Any) -> List[str]:
                return x if isinstance(x, list) else ([] if x is None else [str(x)])
            anomalies_exploded = df_raw.assign(anoms=df_raw['anomalies'].apply(to_list)).explode('anoms')
            anomalies_exploded = anomalies_exploded[anomalies_exploded['anoms'].astype(str).str.len() > 0]
            if not anomalies_exploded.empty:
                anom_counts = anomalies_exploded.groupby('anoms').size().reset_index(name='count').sort_values('count', ascending=False)
                anom_fig = px.bar(anom_counts, x='anoms', y='count', color='count', color_continuous_scale='Turbo', title='Anomaly Types (recent)')
            else:
                anom_fig = px.bar(pd.DataFrame({'anoms': [], 'count': []}), x='anoms', y='count', title='Anomaly Types (recent)')

            # Reputation status pie (colorful)
            rep_counts = df_raw['umbrella_status'].fillna('unknown').replace('', 'unknown').value_counts().reset_index()
            rep_counts.columns = ['status', 'count']
            rep_fig = px.pie(rep_counts, names='status', values='count', color='status', color_discrete_sequence=px.colors.qualitative.Set3, title='Reputation Status (recent)') if not rep_counts.empty else px.pie(pd.DataFrame({'status': [], 'count': []}), names='status', values='count', title='Reputation Status (recent)')

            # QType frequency (color by count)
            qtype_counts = df_raw['qtype'].fillna('NA').value_counts().reset_index()
            qtype_counts.columns = ['qtype', 'count']
            qtype_fig = px.bar(qtype_counts, x='qtype', y='count', color='count', color_continuous_scale='Turbo', title='Query Types (recent)') if not qtype_counts.empty else px.bar(pd.DataFrame({'qtype': [], 'count': []}), x='qtype', y='count', title='Query Types (recent)')

            # Source IP frequency (color by count)
            src_counts = df_raw['src_ip'].fillna('NA').value_counts().reset_index()
            src_counts.columns = ['src_ip', 'count']
            srcip_fig = px.bar(src_counts.head(20), x='src_ip', y='count', color='count', color_continuous_scale='Turbo', title='Top Source IPs (recent)') if not src_counts.empty else px.bar(pd.DataFrame({'src_ip': [], 'count': []}), x='src_ip', y='count', title='Top Source IPs (recent)')

            # Events over time (per minute) with zero-filled minutes
            ts_num = pd.to_numeric(df_raw['timestamp'], errors='coerce')
            ts = pd.to_datetime(ts_num, unit='s', errors='coerce').dropna()
            if not ts.empty:
                minutes = ts.dt.floor('min')
                counts = minutes.value_counts().sort_index()
                full_index = pd.date_range(minutes.min(), minutes.max(), freq='min')
                counts = counts.reindex(full_index, fill_value=0)
                events_per_min = counts.reset_index()
                events_per_min.columns = ['minute', 'count']
            else:
                events_per_min = pd.DataFrame({'minute': [], 'count': []})
            ts_fig = px.line(events_per_min, x='minute', y='count', title='Events per Minute') if not events_per_min.empty else px.line(pd.DataFrame({'minute': [], 'count': []}), x='minute', y='count', title='Events per Minute')
            ts_fig.update_traces(line_color='#00CC96')

            # Hidden geo-map figure (empty)
            geo_empty = px.bar(pd.DataFrame({'country': [], 'count': []}), x='country', y='count', title='')

            return ent_fig, anom_fig, rep_fig, qtype_fig, srcip_fig, ts_fig, geo_empty
        else:
            empty_hist_ent = px.histogram(pd.DataFrame({'entropy': []}), x='entropy', title='Domain Entropy Distribution (recent)')
            empty_anom = px.bar(pd.DataFrame({'anoms': [], 'count': []}), x='anoms', y='count', title='Anomaly Types (recent)')
            empty_pie = px.pie(pd.DataFrame({'status': [], 'count': []}), names='status', values='count', title='Reputation Status (recent)')
            empty_qtype = px.bar(pd.DataFrame({'qtype': [], 'count': []}), x='qtype', y='count', title='Query Types (recent)')
            empty_src = px.bar(pd.DataFrame({'src_ip': [], 'count': []}), x='src_ip', y='count', title='Top Source IPs (recent)')
            empty_ts = px.line(pd.DataFrame({'minute': [], 'count': []}), x='minute', y='count', title='Events per Minute')
            geo_empty = px.bar(pd.DataFrame({'country': [], 'count': []}), x='country', y='count', title='')
            return empty_hist_ent, empty_anom, empty_pie, empty_qtype, empty_src, empty_ts, geo_empty

    # Export CSV of current table rows
    @app.callback(
        Output('download-csv', 'data'),
        Input('btn-export-csv', 'n_clicks'),
        State('events-table', 'data'),
        prevent_initial_call=True
    )
    def export_csv(n_clicks, table_rows):
        try:
            if not table_rows:
                return no_update
            df = pd.DataFrame(table_rows)
            # Ensure consistent column order with the table
            cols = ['timestamp','src_ip','dst_ip','domain','qtype','ips','ttl','record_types','entropy','umbrella_status','umbrella_categories','anomalies']
            for c in cols:
                if c not in df.columns:
                    df[c] = ''
            df = df[cols]
            filename = f"dns_events_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv"
            return dcc.send_data_frame(df.to_csv, filename, index=False)
        except Exception:
            return no_update

    # Export JSON of current table rows
    @app.callback(
        Output('download-json', 'data'),
        Input('btn-export-json', 'n_clicks'),
        State('events-table', 'data'),
        prevent_initial_call=True
    )
    def export_json(n_clicks, table_rows):
        try:
            if not table_rows:
                return no_update
            df = pd.DataFrame(table_rows)
            # Keep the same column order for consistency
            cols = ['timestamp','src_ip','dst_ip','domain','qtype','ips','ttl','record_types','entropy','umbrella_status','umbrella_categories','anomalies']
            for c in cols:
                if c not in df.columns:
                    df[c] = ''
            df = df[cols]
            filename = f"dns_events_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.json"
            # Use records orientation for easy downstream parsing
            json_text = df.to_json(orient='records')
            return dcc.send_string(json_text, filename)
        except Exception:
            return no_update

    return app

    # (Note: additional callbacks should be declared before returning the app)
