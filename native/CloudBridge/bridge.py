"""Original local READ-ONLY adapter. Session state goes only to parent process.
Never accepts service-write operations. No passwords are persisted by this bridge.
"""
import base64, json, logging, os, shutil, sys, tempfile, time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from pathlib import Path
logging.disable(logging.CRITICAL)
from pyicloud import PyiCloudService

folder = os.environ.get('GLASSWIDGETS_CLOUD_TEMP') or tempfile.mkdtemp(prefix='gw-cloud-')
os.makedirs(folder, exist_ok=True)
api = None
username = ''
last_code_request = 0
code_requested = False
delivery_error = None

def saved():
    # Cookie/session material is encrypted by Electron before being saved.
    files = {}
    for p in Path(folder).iterdir():
        if p.is_file() and p.stat().st_size < 2_000_000:
            files[p.name] = base64.b64encode(p.read_bytes()).decode()
    return {'user': username, 'files': files}

def restore(bundle):
    for name, value in bundle.get('files', {}).items():
        if Path(name).name != name or len(value) > 3_000_000:
            raise ValueError('Invalid saved session')
        (Path(folder) / name).write_bytes(base64.b64decode(value))

def emit(request_id, value):
    value['id'] = request_id
    value['_session'] = saved()
    print(json.dumps(value, ensure_ascii=False), flush=True)

def state():
    if api is None:
        return {'connected': False, 'state': 'signed_out'}
    if api.requires_2fa:
        return {'connected': False, 'state': 'code_required', 'delivery': api.two_factor_delivery_method, 'requested': code_requested, 'error': delivery_error}
    if api.requires_2sa:
        return {'connected': False, 'state': 'unsupported_2sa', 'error': 'נדרש אימות ישן שאינו נתמך. פתח את האתר הרשמי.'}
    return {'connected': True, 'state': 'connected'}

def request_code(retry=False):
    global last_code_request, code_requested, delivery_error
    if api is None or not api.requires_2fa:
        return state()
    if retry and time.time() - last_code_request < 60:
        return {**state(), 'error': 'אפשר לבקש קוד שוב אחרי דקה'}
    last_code_request = time.time()
    delivery_error = None
    try:
        if retry:
            api.use_existing_trusted_device_code()
        code_requested = bool(api.request_2fa_code())
        if not code_requested:
            delivery_error = 'Apple לא אישרה בקשת קוד. אפשר להשתמש בקוד מהמכשיר המהימן או להיכנס באתר הרשמי.'
    except Exception as e:
        code_requested = False
        delivery_error = type(e).__name__ + ': בקשת קוד נכשלה. נסה שוב או השתמש בקוד מהמכשיר המהימן.'
    return state()

def calendar_event(ev):
    def stamp(value, zone):
        if not isinstance(value, (list, tuple)) or len(value) < 6:
            raise ValueError('Invalid calendar date')
        dt = datetime(*map(int, value[1:6]), tzinfo=zone)
        return int(dt.timestamp() * 1000)
    try:
        zone = ZoneInfo(ev.get('tz') or 'Asia/Jerusalem')
    except Exception:
        zone = ZoneInfo('Asia/Jerusalem')
    return {'id': ev.get('guid'), 'title': ev.get('title') or '', 'start': stamp(ev['startDate'], zone), 'end': stamp(ev['endDate'], zone), 'allDay': bool(ev.get('allDay'))}

def fetch_data():
    status = state()
    if not status.get('connected'):
        return status
    out = {**status, 'notes': [], 'reminders': [], 'calendar': [], 'errors': {}, 'at': __import__('time').time() * 1000}
    try:
        for summary in api.notes.recents(limit=8):
            item = {'id': summary.id, 'title': summary.title or ''}
            try:
                full = api.notes.get(summary.id, with_attachments=False)
                item['text'] = (full.text or '')[:12000]
            except Exception:
                item['error'] = 'תוכן הפתק אינו זמין (ייתכן שהוא נעול)'
            out['notes'].append(item)
    except Exception as e:
        out['errors']['notes'] = type(e).__name__ + ': לא ניתן לקרוא פתקים כרגע'
    try:
        for rem in api.reminders.reminders():
            if rem.completed:
                continue
            out['reminders'].append({'id': rem.id, 'title': rem.title or '', 'due': str(rem.due_date) if rem.due_date else None})
            if len(out['reminders']) >= 20:
                break
    except Exception as e:
        out['errors']['reminders'] = type(e).__name__ + ': לא ניתן לקרוא תזכורות כרגע'
    try:
        now = datetime.now(ZoneInfo('Asia/Jerusalem'))
        for ev in api.calendar.get_events(from_dt=now-timedelta(days=1), to_dt=now+timedelta(days=8)):
            out['calendar'].append(calendar_event(ev))
    except Exception as e:
        out['errors']['calendar'] = type(e).__name__ + ': לא ניתן לקרוא לוח שנה כרגע'
    return out

try:
    for line in sys.stdin:
        request = {}
        try:
            request = json.loads(line)
            action = request.get('action')
            if action == 'login':
                username = str(request.get('user', '')).strip()
                api = PyiCloudService(username, request.get('password'), cookie_directory=folder, accept_terms=False, pause_2fa=False)
                code_requested = False
                delivery_error = None
                emit(request.get('id'), request_code() if api.requires_2fa else state())
            elif action == 'resume':
                bundle = request.get('session') or {}
                username = bundle.get('user', '')
                restore(bundle)
                if username:
                    api = PyiCloudService(username, cookie_directory=folder, accept_terms=False, pause_2fa=False, authenticate=False)
                    api.authenticate(pause_2fa=False)
                emit(request.get('id'), state())
            elif action == 'request_code':
                emit(request.get('id'), request_code(retry=True))
            elif action == 'code':
                if api is None:
                    raise ValueError('No login in progress')
                if request.get('manual'):
                    api.use_existing_trusted_device_code()
                if not api.validate_2fa_code(str(request.get('code', ''))):
                    emit(request.get('id'), {'connected': False, 'state': 'code_required', 'error': 'קוד האימות לא התקבל'})
                else:
                    api.trust_session()
                    emit(request.get('id'), state())
            elif action == 'refresh':
                emit(request.get('id'), fetch_data())
            elif action == 'status':
                emit(request.get('id'), state())
            else:
                emit(request.get('id'), {'connected': False, 'error': 'Unsupported read-only action'})
        except Exception as e:
            # Exception text may contain URLs/tokens. Return only type and generic guidance.
            emit(request.get('id'), {'connected': False, 'state': 'error', 'error': type(e).__name__ + ': ההתחברות או הקריאה נכשלה. נסה כניסה מחדש, או פתח את האתר הרשמי.'})
finally:
    shutil.rmtree(folder, ignore_errors=True)
