# app.py - Main Flask Application
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///elearning.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Dodaj filtr fromjson do Jinja2
@app.template_filter('fromjson')
def fromjson_filter(value):
    try:
        return json.loads(value) if value else {}
    except (json.JSONDecodeError, TypeError):
        return {}

# Models (M w MVC)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacja z postępami użytkownika
    progress = db.relationship('UserProgress', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Section(db.Model):
    """Dział główny"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    order_index = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacje
    subsections = db.relationship('Subsection', backref='section', lazy=True, cascade='all, delete-orphan')
    pages = db.relationship('Page', backref='section', lazy=True, cascade='all, delete-orphan')

class Subsection(db.Model):
    """Poddział"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    section_id = db.Column(db.Integer, db.ForeignKey('section.id'), nullable=False)
    order_index = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacje
    pages = db.relationship('Page', backref='subsection', lazy=True, cascade='all, delete-orphan')

class Page(db.Model):
    """Strona z treścią"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    section_id = db.Column(db.Integer, db.ForeignKey('section.id'), nullable=False)
    subsection_id = db.Column(db.Integer, db.ForeignKey('subsection.id'), nullable=True)
    order_index = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacje
    content_blocks = db.relationship('ContentBlock', backref='page', lazy=True, cascade='all, delete-orphan', order_by='ContentBlock.order_index')

class ContentBlock(db.Model):
    """Blok treści - kafelek na stronie"""
    id = db.Column(db.Integer, primary_key=True)
    page_id = db.Column(db.Integer, db.ForeignKey('page.id'), nullable=False)
    block_type = db.Column(db.String(50), nullable=False)  # 'text', 'video', 'slides', 'exercise', 'calculation_link'
    title = db.Column(db.String(200))
    content = db.Column(db.Text)  # JSON dla różnych typów treści
    order_index = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserProgress(db.Model):
    """Postęp użytkownika"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    page_id = db.Column(db.Integer, db.ForeignKey('page.id'), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    score = db.Column(db.Float, default=0.0)
    completion_date = db.Column(db.DateTime)
    exercise_data = db.Column(db.Text)  # JSON z wynikami ćwiczeń

# Controllers (C w MVC)
class AuthController:
    @staticmethod
    def login(username, password):
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return True
        return False
    
    @staticmethod
    def logout():
        session.clear()
    
    @staticmethod
    def is_logged_in():
        return 'user_id' in session
    
    @staticmethod
    def is_admin():
        return session.get('is_admin', False)
    
    @staticmethod
    def require_login():
        if not AuthController.is_logged_in():
            return redirect(url_for('index'))
        return None
    
    @staticmethod
    def require_admin():
        if not AuthController.is_admin():
            flash('Brak uprawnień administratora', 'error')
            return redirect(url_for('dashboard'))
        return None

class ContentController:
    @staticmethod
    def get_sections():
        return Section.query.order_by(Section.order_index).all()
    
    @staticmethod
    def get_section(section_id):
        return Section.query.get_or_404(section_id)
    
    @staticmethod
    def get_page(page_id):
        return Page.query.get_or_404(page_id)
    
    @staticmethod
    def get_content_blocks(page_id):
        return ContentBlock.query.filter_by(page_id=page_id).order_by(ContentBlock.order_index).all()
    
    @staticmethod
    def create_section(title, description):
        max_order = db.session.query(db.func.max(Section.order_index)).scalar() or 0
        section = Section(title=title, description=description, order_index=max_order + 1)
        db.session.add(section)
        db.session.commit()
        return section
    
    @staticmethod
    def create_subsection(section_id, title, description):
        max_order = db.session.query(db.func.max(Subsection.order_index)).filter_by(section_id=section_id).scalar() or 0
        subsection = Subsection(
            section_id=section_id, 
            title=title, 
            description=description, 
            order_index=max_order + 1
        )
        db.session.add(subsection)
        db.session.commit()
        return subsection
    
    @staticmethod
    def create_page(section_id, subsection_id, title):
        max_order = db.session.query(db.func.max(Page.order_index)).filter_by(section_id=section_id).scalar() or 0
        page = Page(
            section_id=section_id,
            subsection_id=subsection_id,
            title=title,
            order_index=max_order + 1
        )
        db.session.add(page)
        db.session.commit()
        return page
    
    @staticmethod
    def create_content_block(page_id, block_type, title, content):
        max_order = db.session.query(db.func.max(ContentBlock.order_index)).filter_by(page_id=page_id).scalar() or 0
        block = ContentBlock(
            page_id=page_id,
            block_type=block_type,
            title=title,
            content=content,
            order_index=max_order + 1
        )
        db.session.add(block)
        db.session.commit()
        return block

# Routes (V w MVC)
@app.route('/')
def index():
    if AuthController.is_logged_in():
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if AuthController.login(username, password):
        flash('Zalogowano pomyślnie!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Nieprawidłowe dane logowania', 'error')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    AuthController.logout()
    flash('Wylogowano pomyślnie', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    redirect_response = AuthController.require_login()
    if redirect_response:
        return redirect_response
    
    sections = ContentController.get_sections()
    return render_template('dashboard.html', sections=sections)

@app.route('/section/<int:section_id>')
def view_section(section_id):
    redirect_response = AuthController.require_login()
    if redirect_response:
        return redirect_response
    
    section = ContentController.get_section(section_id)
    return render_template('section.html', section=section)

@app.route('/page/<int:page_id>')
def view_page(page_id):
    redirect_response = AuthController.require_login()
    if redirect_response:
        return redirect_response
    
    page = ContentController.get_page(page_id)
    content_blocks = ContentController.get_content_blocks(page_id)
    
    return render_template('page.html', page=page, content_blocks=content_blocks)

@app.route('/admin')
def admin_panel():
    redirect_response = AuthController.require_login()
    if redirect_response:
        return redirect_response
    
    redirect_response = AuthController.require_admin()
    if redirect_response:
        return redirect_response
    
    sections = ContentController.get_sections()
    return render_template('admin/panel.html', sections=sections)

@app.route('/admin/section/create', methods=['GET', 'POST'])
def admin_create_section():
    redirect_response = AuthController.require_login()
    if redirect_response:
        return redirect_response
    
    redirect_response = AuthController.require_admin()
    if redirect_response:
        return redirect_response
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        ContentController.create_section(title, description)
        flash('Dział został utworzony!', 'success')
        return redirect(url_for('admin_panel'))
    
    return render_template('admin/create_section.html')

@app.route('/admin/section/<int:section_id>/subsection/create', methods=['GET', 'POST'])
def admin_create_subsection(section_id):
    redirect_response = AuthController.require_login()
    if redirect_response:
        return redirect_response
    
    redirect_response = AuthController.require_admin()
    if redirect_response:
        return redirect_response
    
    section = ContentController.get_section(section_id)
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        ContentController.create_subsection(section_id, title, description)
        flash('Poddział został utworzony!', 'success')
        return redirect(url_for('admin_edit_section', section_id=section_id))
    
    return render_template('admin/create_subsection.html', section=section)

@app.route('/admin/section/<int:section_id>/edit')
def admin_edit_section(section_id):
    redirect_response = AuthController.require_login()
    if redirect_response:
        return redirect_response
    
    redirect_response = AuthController.require_admin()
    if redirect_response:
        return redirect_response
    
    section = ContentController.get_section(section_id)
    return render_template('admin/edit_section.html', section=section)

@app.route('/admin/page/<int:page_id>/edit')
def admin_edit_page(page_id):
    redirect_response = AuthController.require_login()
    if redirect_response:
        return redirect_response
    
    redirect_response = AuthController.require_admin()
    if redirect_response:
        return redirect_response
    
    page = ContentController.get_page(page_id)
    content_blocks = ContentController.get_content_blocks(page_id)
    
    return render_template('admin/edit_page.html', page=page, content_blocks=content_blocks)

@app.route('/admin/page/create', methods=['GET', 'POST'])
def admin_create_page():
    redirect_response = AuthController.require_login()
    if redirect_response:
        return redirect_response
    
    redirect_response = AuthController.require_admin()
    if redirect_response:
        return redirect_response
    
    if request.method == 'POST':
        section_id = int(request.form['section_id'])
        subsection_id = request.form.get('subsection_id')
        if subsection_id:
            subsection_id = int(subsection_id)
        title = request.form['title']
        
        page = ContentController.create_page(section_id, subsection_id, title)
        flash('Strona została utworzona!', 'success')
        return redirect(url_for('admin_edit_page', page_id=page.id))
    
    sections = ContentController.get_sections()
    return render_template('admin/create_page.html', sections=sections)

@app.route('/admin/content-block/create/<int:page_id>', methods=['POST'])
def admin_create_content_block(page_id):
    redirect_response = AuthController.require_login()
    if redirect_response:
        return redirect_response
    
    redirect_response = AuthController.require_admin()
    if redirect_response:
        return redirect_response
    
    block_type = request.form['block_type']
    title = request.form.get('title', '')
    content = request.form.get('content', '')
    
    # Dla różnych typów bloków, przygotuj zawartość jako JSON
    if block_type in ['video', 'slides']:
        content_data = {
            'url': request.form.get('url', ''),
            'description': request.form.get('description', '')
        }
        content = json.dumps(content_data)
    elif block_type == 'exercise':
        content_data = {
            'question': request.form.get('question', ''),
            'options': request.form.get('options', '').split('\n'),
            'correct_answer': request.form.get('correct_answer', '')
        }
        content = json.dumps(content_data)
    elif block_type == 'calculation_link':
        content_data = {
            'url': request.form.get('calculation_url', ''),
            'description': request.form.get('description', '')
        }
        content = json.dumps(content_data)
    
    ContentController.create_content_block(page_id, block_type, title, content)
    flash('Blok treści został dodany!', 'success')
    return redirect(url_for('admin_edit_page', page_id=page_id))

# API endpoints dla AJAX
@app.route('/api/subsections/<int:section_id>')
def api_get_subsections(section_id):
    section = Section.query.get_or_404(section_id)
    subsections = [{'id': s.id, 'title': s.title} for s in section.subsections]
    return jsonify(subsections)

def init_database():
    """Inicjalizacja bazy danych z domyślnymi użytkownikami"""
    with app.app_context():
        db.create_all()
        
        # Sprawdź czy użytkownicy już istnieją
        if User.query.count() == 0:
            # Utwórz administratora
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin')
            db.session.add(admin)
            
            # Utwórz zwykłego użytkownika
            user = User(username='user', is_admin=False)
            user.set_password('user')
            db.session.add(user)
            
            db.session.commit()
            print("Utworzono domyślnych użytkowników:")
            print("Administrator: admin/admin")
            print("Użytkownik: user/user")

if __name__ == '__main__':
    init_database()
    app.run(debug=True)