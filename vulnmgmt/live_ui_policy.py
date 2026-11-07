"""Display policy only; backend authorization remains the authority."""

def replay_only(config=None):
    if config is None:
        from .runtime_binding import runtime_configuration
        config = runtime_configuration()
    return config.get('live_enabled') is False


def mode_radio(target, label, *, index=0, key, **kwargs):
    if replay_only():
        # Do not read or replace a saved Live preference or stale widget state.
        target.caption(label+': Replay · Live AI unavailable in this preview')
        return 'Replay'
    return target.radio(label, ['Replay', 'Live AI'], index=index, key=key, **kwargs)


def spend_checkbox(target, label, **kwargs):
    if replay_only():
        return False
    return target.checkbox(label, **kwargs)
