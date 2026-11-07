"""Supported Streamlit/Altair presentation primitives; no custom HTML or internal CSS."""
import json
from datetime import datetime
import altair as alt
import pandas as pd
import streamlit as st

SEVERITY = {'Critical': '#DC2626', 'High': '#EA580C', 'Medium': '#D97706',
            'Low': '#0D9488', 'Informational': '#64748B', 'Unknown': '#64748B'}
STATUS = {'Open': '#38BDF8', 'In Remediation': '#38BDF8', 'Pending Verification': '#F59E0B',
          'Verified Remediated': '#0D9488', 'Closed': '#0D9488', 'Reopened': '#EA580C',
          'Risk Accepted': '#64748B', 'Escalated': '#38BDF8'}


def readable(value, key=''):
    if value is None:
        return 'Unknown'
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return ', '.join(value)
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, str) and (key.endswith('_at') or key in ('as_of', 'first_seen', 'last_seen')):
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00')).strftime('%d %b %Y %H:%M UTC')
        except ValueError:
            pass
    return value


def table(rows, columns=None, height=260, key=None, *, alt=None):
    if not rows:
        st.caption('No matching records. Choose a workflow step or adjust the filters.')
        return
    values = [{k.replace('_', ' ').title(): readable(r.get(k), k)
               for k in (columns or list(r))} for r in rows]
    # Arrow cannot infer a numeric column containing the display string Unknown.
    # Format the whole nullable display column consistently; exports retain types.
    for column in {k for row in values for k in row}:
        cells = [row.get(column) for row in values]
        if 'Unknown' in cells and any(isinstance(v, (int, float, bool)) for v in cells):
            for row in values:
                if row.get(column) is not None:
                    row[column] = str(row[column])
    st.dataframe(values, width='stretch', height=min(height, 38+35*len(rows)), hide_index=True, key=key, alt=alt)


def horizontal_chart(counts, title, palette=None, unit='Obligations', *, tick_count=5):
    """Bounded chart, explicit quantitative count axis and readable horizontal labels."""
    if not counts:
        st.caption(title+' · no findings yet')
        return
    df = pd.DataFrame([{'Category': k, 'Records': v} for k, v in counts.items()]).sort_values(
        ['Records', 'Category'], ascending=[False, True])
    color = alt.Color('Category:N', legend=None,
        scale=alt.Scale(domain=list(palette), range=list(palette.values()))) if palette else alt.value('#38BDF8')
    bars = alt.Chart(df).mark_bar(cornerRadiusEnd=3, size=16).encode(
        x=alt.X('Records:Q', title=unit, axis=alt.Axis(tickMinStep=1, tickCount=tick_count, format="d"),
                scale=alt.Scale(domain=[0, max(df.Records)*1.18])),
        y=alt.Y('Category:N', sort=list(df.Category), title=None, axis=alt.Axis(labelLimit=230), scale=alt.Scale(type='band', paddingInner=0.35, paddingOuter=0.2)),
        color=color, tooltip=['Category:N', 'Records:Q'])
    labels = bars.mark_text(align='left', dx=6, color='#F8FAFC').encode(text='Records:Q')
    # Streamlit otherwise injects autosize=fit, shrinking the *plot* to make axes
    # and title fit inside the supplied height. Preserve 32px data rows and fit
    # width only; title/axis height is additional, never subtracted from rows.
    chart = (bars+labels).properties(height=alt.Step(32), title=title,
        autosize=alt.AutoSizeParams(type='fit-x', contains='padding', resize=True)
    ).configure_view(stroke=None).configure_axis(
        labelColor='#F8FAFC', titleColor='#F8FAFC', gridColor='#26364D'
    ).configure_title(color='#F8FAFC')
    st.altair_chart(chart, width='stretch', theme=None)


def source_cards(sources):
    for s in sources:
        with st.container(border=True):
            st.write(s['publisher']+' · '+s['fetch_status'])
            st.write(s['url'])
            st.caption('Retrieved '+s['retrieved_at']+' · SHA-256 '+str(s['content_hash']))
            if s.get('error'):
                st.warning(s['error'])


def short_result(result):
    if result.get('outcome'):
        return result['outcome']+(' · '+', '.join(result.get('reasons', [])) if result.get('reasons') else '')
    if result.get('decision'):
        return 'Decision recorded: '+result['decision']
    if 'imports' in result:
        return f"Import complete · {sum(r['new_rows'] for r in result['imports'])} new raw rows; repeat exports retained as no-ops"
    if 'summary' in result and 'cves_enriched' in result['summary']:
        return f"Replay complete · {result['summary']['cves_enriched']} CVEs enriched; no live calls or current retrievals"
    if result.get('ticket_status'):
        return 'Scanner result recorded · ticket '+result['ticket_status']
    if result.get('intent'):
        return 'Resolver reply processed · '+result['intent']+' (completion requires scanner verification)'
    if result.get('synthetic_clock'):
        return 'Synthetic clock advanced · ready for a subsequent assessment'
    return 'Local action recorded. Inspect the stored output and validation checkpoint.'
