from pathlib import Path

from aisast.context.context_builder import ContextBuilder
from aisast.models import Candidate, Location
from aisast.verifier.prompts import guided_profiles, render_prompt


def write(root: Path, file: str, code: str) -> None:
    path = root / file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code)


def candidate(file: str, line: int, cwe: int = 79) -> Candidate:
    loc = Location(file=file, line=line)
    return Candidate(candidate_id='fixture', repository_sha='fixture', rule_id='fixture',
                     cwe=cwe, title='fixture', primary_location=loc, sink=loc)


def code(packet) -> str:
    return '\n'.join(block.code for block in packet.evidence)


def test_template_loop_renderer_model_write_and_form_type(tmp_path):
    write(tmp_path, 'models.py', "class Memo:\n    text = Column(String)\n    def __init__(self, text):\n        self.text = text\n")
    write(tmp_path, 'forms.py', "class MemoForm:\n    text = TextAreaField(validators=[DataRequired()])\n")
    write(tmp_path, 'views.py', "from flask import render_template, request\nfrom models import Memo as Entry\nfrom forms import MemoForm\ndef read():\n    rows = Entry.query.all()\n    return render_template('feed.html', entries=rows)\ndef save():\n    form = MemoForm(request.form)\n    item = Entry(text=form.text.data)\n    db.session.add(item)\n")
    write(tmp_path, 'templates/feed.html', '{% for item in entries %}\n' + '\n' * 15 + '{{ item.text | safe }}\n{% endfor %}\n')
    packet = ContextBuilder(tmp_path).packet(candidate('templates/feed.html', 17))
    text = code(packet)
    assert 'entries=rows' in text
    assert 'item = Entry(text=form.text.data)' in text
    assert 'TextAreaField(validators=[DataRequired()])' in text
    assert 'self.text = text' in text
    assert '{% for item in entries %}' in text
    assert not packet.context_truncated


def test_package_reexport_and_same_named_unrelated_model(tmp_path):
    write(tmp_path, 'package/__init__.py', 'from .data import *\nfrom .other import *\n')
    write(tmp_path, 'package/data.py', 'class Item:\n    title = Column(String)\n')
    write(tmp_path, 'package/other.py', 'class Other:\n    pass\n')
    write(tmp_path, 'unrelated.py', 'class Item:\n    title = Column(String)\ndef irrelevant():\n    item = Item(title="unrelated")\n')
    write(tmp_path, 'views.py', 'from flask import render_template, request\nfrom package import Item\ndef view():\n    return render_template("page.html", item=Item.query.first())\ndef write_item():\n    row = Item(title=request.form["title"])\n')
    write(tmp_path, 'templates/page.html', '{{ item.title | safe }}\n')
    packet = ContextBuilder(tmp_path).packet(candidate('templates/page.html', 1))
    assert 'request.form["title"]' in code(packet)
    assert not any(e.file == 'unrelated.py' for e in packet.evidence)


def test_django_context_dictionary_assignment_and_update(tmp_path):
    write(tmp_path, 'views.py', 'from django.shortcuts import render\ndef view(request):\n    context = {}\n    context["name"] = request.GET["name"]\n    context.update(label=request.GET["label"])\n    return render(request, "page.html", context)\n')
    write(tmp_path, 'templates/page.html', '{{ name | safe }} {{ label | safe }}\n')
    packet = ContextBuilder(tmp_path).packet(candidate('templates/page.html', 1))
    assert 'request.GET["name"]' in code(packet)
    assert 'request.GET["label"]' in code(packet)
    assert len([e for e in packet.context_resolution if e['kind'] == 'template_context_binding']) == 2


def test_get_template_render_and_field_type(tmp_path):
    write(tmp_path, 'models.py', 'class Review:\n    date = DateField()\n    def chart_date(self):\n        return self.date.isoformat()\n')
    write(tmp_path, 'views.py', 'from django.template.loader import get_template\nfrom models import Review\ndef view(request):\n    reviews = Review.objects.all()\n    t = get_template("chart.html")\n    return t.render({"reviews": reviews})\n')
    write(tmp_path, 'template/chart.html', '{% for review in reviews %}\n"{{ review.chart_date }}"\n{% endfor %}\n')
    packet = ContextBuilder(tmp_path).packet(candidate('template/chart.html', 2))
    assert 'date = DateField()' in code(packet)
    assert 'return self.date.isoformat()' in code(packet)


def test_sql_row_provenance_is_possible_and_includes_input(tmp_path):
    write(tmp_path, 'views.py', 'from flask import render_template, request\ndef load_user(uid):\n    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))\n    return cursor.fetchone()\ndef profile():\n    user = load_user(1)\n    return render_template("profile.html", user=user)\ndef edit():\n    country = request.form["country"]\n    cursor.execute("UPDATE users SET country = ? WHERE id = ?", (country, 1))\n')
    write(tmp_path, 'templates/profile.html', '{{ user.country | safe }}\n')
    packet = ContextBuilder(tmp_path).packet(candidate('templates/profile.html', 1))
    assert 'country = request.form["country"]' in code(packet)
    events = [e for e in packet.context_resolution if e['kind'] == 'sql_possible_field_write']
    assert events and all(e['certainty'] == 'syntactic_possible' for e in events)


def test_flask_decorator_and_default_html_semantics(tmp_path):
    write(tmp_path, 'app.py', 'from flask import Flask, request\napp = Flask(__name__)\n@app.route("/hello")\ndef hello():\n    return request.args["name"]\n')
    packet = ContextBuilder(tmp_path).packet(candidate('app.py', 5))
    assert '@app.route("/hello")' in code(packet)
    assert any('HTML response' in fact for fact in packet.framework_facts)


def test_django_url_binding_uses_qualified_import(tmp_path):
    write(tmp_path, 'views.py', 'from django.http import HttpResponse\ndef profile(request, uid):\n    return HttpResponse(uid)\n')
    write(tmp_path, 'other.py', 'def profile(request, uid):\n    return uid\n')
    write(tmp_path, 'urls.py', 'from django.conf.urls import url\nimport views as handlers\nimport other\nurlpatterns = [url(r"^(?P<uid>[0-9]+)$", handlers.profile), url("other", other.profile)]\n')
    packet = ContextBuilder(tmp_path).packet(candidate('views.py', 3))
    events = [e for e in packet.context_resolution if e['kind'] == 'django_url_binding']
    assert len(events) == 1
    assert '[0-9]+' in code(packet)


def test_graphql_argument_binding(tmp_path):
    write(tmp_path, 'schema.py', 'import graphene\nclass Query(graphene.ObjectType):\n    records = graphene.List(Row, search=graphene.String())\n    def resolve_records(self, info, search=None):\n        return db.execute("SELECT * FROM records WHERE name=" + search)\n')
    packet = ContextBuilder(tmp_path).packet(candidate('schema.py', 5, 89))
    assert 'search=graphene.String()' in code(packet)
    assert any(e['kind'] == 'graphql_argument_binding' for e in packet.context_resolution)


def test_typed_field_expansion_adds_sibling_field_origin(tmp_path):
    write(tmp_path, 'models.py', 'class Note:\n    text = Column(String)\n    author = Column(String)\n')
    write(tmp_path, 'views.py', 'from flask import render_template, request\nfrom models import Note\ndef view():\n    return render_template("page.html", note=Note.query.first())\ndef text_writer():\n    Note(text=request.form["text"])\ndef author_writer():\n    Note(author=request.form["author"])\n')
    write(tmp_path, 'templates/page.html', '{{ note.text | safe }}\n{{ note.author | safe }}\n')
    builder = ContextBuilder(tmp_path)
    initial = builder.packet(candidate('templates/page.html', 1))
    expanded = builder.packet(candidate('templates/page.html', 1), ['Field origin: note.author'])
    assert 'request.form["author"]' not in code(initial)
    assert 'request.form["author"]' in code(expanded)
    assert {e.id for e in initial.evidence} != {e.id for e in expanded.evidence}


def test_helper_parameter_gets_caller_input(tmp_path):
    write(tmp_path, 'models.py', 'class Entry:\n    text = Column(String)\n')
    write(tmp_path, 'views.py', 'from flask import request, render_template\nfrom models import Entry\ndef view():\n    return render_template("page.html", entry=Entry.query.first())\ndef store(value):\n    row = Entry(text=value)\ndef endpoint():\n    store(request.form["message"])\n')
    write(tmp_path, 'templates/page.html', '{{ entry.text | safe }}\n')
    packet = ContextBuilder(tmp_path).packet(candidate('templates/page.html', 1))
    assert 'store(request.form["message"])' in code(packet)
    assert any(e['kind'] == 'caller_argument_binding' for e in packet.context_resolution)


def test_unresolved_parse_failures_and_budget_are_logged(tmp_path):
    write(tmp_path, 'broken.py', 'def broken(:\n')
    write(tmp_path, 'views.py', 'from flask import render_template, request\ndef view():\n    value = request.args["name"]\n    return render_template("page.html", name=value)\n')
    write(tmp_path, 'templates/page.html', '{{ name | safe }}\n')
    packet = ContextBuilder(tmp_path, max_chars=90).packet(candidate('templates/page.html', 1))
    assert packet.context_truncated
    assert any(e['kind'] == 'index_parse_errors' for e in packet.context_resolution)
    assert any(e.get('status') == 'omitted_by_budget' for e in packet.context_resolution)


def test_guided_prompt_consistent_unknown_policy(tmp_path):
    write(tmp_path, 'template.html', '{{ unknown | safe }}\n')
    packet = ContextBuilder(tmp_path).packet(candidate('template.html', 1), ['Field origin: unknown'])
    prompt = render_prompt(packet)
    assert 'verdict False Positive' not in prompt
    assert 'Field origin: user.country' in prompt
    assert any(e['status'] == 'unresolved' for e in packet.context_resolution)
    assert all('verdict False Positive' not in question for questions in guided_profiles().values() for question in questions)


def test_typed_template_request_adds_contents_and_nested_loader(tmp_path):
    write(tmp_path, 'apps/view.py', 'from pathlib import Path\nfrom jinja2 import Environment, FileSystemLoader\nloader = FileSystemLoader(Path(__file__).parent / "templates" / "custom")\nenv = Environment(loader=loader)\ndef view(value):\n    template = env.get_template("page.html")\n    return template.render(value=value)\n')
    write(tmp_path, 'apps/templates/custom/page.html', '{{ value }}\n')
    builder = ContextBuilder(tmp_path)
    packet = builder.packet(candidate('apps/view.py', 7), ['Template renderer: page.html'])
    assert any(e.file == 'apps/templates/custom/page.html' for e in packet.evidence)
    assert any(e['kind'] == 'template_contents' and e['status'] == 'located' for e in packet.context_resolution)


def test_typed_template_request_rejects_traversal(tmp_path):
    write(tmp_path, 'app.py', 'def handler():\n    return 1\n')
    packet = ContextBuilder(tmp_path).packet(candidate('app.py', 2), ['Template contents: ../outside.html'])
    assert all(e.file == 'app.py' for e in packet.evidence)


def test_source_function_retains_decorator_and_framework_imports(tmp_path):
    write(tmp_path, 'views.py', 'from flask import Flask\napp = Flask(__name__)\n@app.route("/value/<value>")\ndef handler(value):\n    return helper(value)\n')
    write(tmp_path, 'sink.py', 'def helper(value):\n    return cursor.execute(value)\n')
    c = candidate('sink.py', 2, 89).model_copy(update={'source':Location(file='views.py', line=5)})
    packet = ContextBuilder(tmp_path).packet(c)
    assert '@app.route("/value/<value>")' in code(packet)
    assert 'from flask import Flask' in code(packet)


def test_http_handler_path_semantics_require_real_base_binding(tmp_path):
    write(tmp_path, 'app.py', 'from http.server import BaseHTTPRequestHandler as Handler\nclass Server(Handler):\n    def do_GET(self):\n        return open(self.path).read()\n')
    packet = ContextBuilder(tmp_path).packet(candidate('app.py', 4, 22))
    assert 'class Server(Handler):' in code(packet)
    assert any('client HTTP request path' in fact for fact in packet.framework_facts)
    write(tmp_path, 'other.py', 'class BaseHTTPRequestHandler:\n    pass\nclass Server(BaseHTTPRequestHandler):\n    def do_GET(self):\n        return open(self.path).read()\n')
    packet = ContextBuilder(tmp_path).packet(candidate('other.py', 5, 22))
    assert not any('client HTTP request path' in fact for fact in packet.framework_facts)


def test_window_ending_mid_call_adds_complete_arguments(tmp_path):
    write(tmp_path, 'app.py', 'setting = 1\n' + '\n' * 6 + 'def handler(request):\n    return render(\n        user_input=request.args["value"]\n    )\n')
    packet = ContextBuilder(tmp_path).packet(candidate('app.py', 1))
    assert 'user_input=request.args["value"]' in code(packet)


def test_flash_context_collects_possible_qualified_producers(tmp_path):
    write(tmp_path, 'views.py', 'from flask import flash as notify, request\ndef view():\n    value = request.args["message"]\n    notify(value)\n')
    write(tmp_path, 'other.py', 'def flash(value):\n    pass\ndef view():\n    flash("unrelated")\n')
    write(tmp_path, 'templates/page.html', '{% with messages = get_flashed_messages() %}\n{% for message in messages %}\n{{ message | safe }}\n{% endfor %}\n{% endwith %}\n')
    packet = ContextBuilder(tmp_path).packet(candidate('templates/page.html', 3))
    assert 'request.args["message"]' in code(packet)
    assert 'notify(value)' in code(packet)
    assert not any(e.file == 'other.py' for e in packet.evidence)
    assert any(e['kind'] == 'flask_possible_flash_producer' for e in packet.context_resolution)
    assert any('completeness are not proven' in fact for fact in packet.framework_facts)


def test_flash_binding_expires_and_shadowed_producer_is_excluded(tmp_path):
    write(tmp_path, 'views.py', 'from flask import flash\ndef view():\n    flash = custom\n    flash("not Flask")\n')
    write(tmp_path, 'templates/page.html', '{% with messages = get_flashed_messages() %}\n{{ messages | safe }}\n{% endwith %}\n{{ unrelated | safe }}\n')
    active = ContextBuilder(tmp_path).packet(candidate('templates/page.html', 2))
    assert not any(e['kind'] == 'flask_possible_flash_producer' for e in active.context_resolution)
    inactive = ContextBuilder(tmp_path).packet(candidate('templates/page.html', 4))
    assert not any(e['kind'] == 'template_flash_binding' for e in inactive.context_resolution)
