from flask import Flask, render_template, request,redirect, url_for,flash, get_flashed_messages
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
import requests
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField, IntegerField
from wtforms.validators import InputRequired, Email, Length, ValidationError
import secrets
import email_validator
from flask_bcrypt import generate_password_hash, check_password_hash, Bcrypt
from sqlalchemy.sql.expression import func 
from random import choice, random
from sqlalchemy.orm import relationship
from sqlalchemy import and_
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  
app.config['SECRET_KEY'] = secrets.token_hex(16)


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
apiKey = "cd72899202fc4fc3eeccc95c747c6f97"
hashed_password = generate_password_hash("user_password").decode('utf-8')


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(255), nullable=False)
    correct_answer = db.Column(db.String(255), nullable=False)
    incorrect_answers = db.Column(db.String(1000), nullable=False)
    incorrect2_answers = db.Column(db.String(1000), nullable=False)
    incorrect3_answers = db.Column(db.String(1000), nullable=False)
    points = db.Column(db.Integer, nullable=False)


    @property
    def all_answers(self):
        return [self.correct_answer] + self.incorrect_answers.split(',') + self.incorrect2_answers.split(',') + self.incorrect3_answers.split(',')


class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    user_answer = db.Column(db.String(255), nullable=False)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    score = db.Column(db.Integer, default=0, nullable=False)
    answers = relationship('Answer', backref='user', lazy=True)
    last_question_id = db.Column(db.Integer, db.ForeignKey('question.id'))
    last_question = relationship('Question', foreign_keys=[last_question_id], backref='user', lazy=True)

    def get_id(self):
        return str(self.id)

    def is_active(self):
        return True
    
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = generate_password_hash(password).decode('utf-8')

class RegistrationForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('E-posta', validators=[InputRequired(), Email(message='Geçerli bir e-posta adresi girin'), Length(max=50)])
    password = PasswordField('Parola', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Kayıt Ol')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Bu e-posta adresi zaten kullanımda.')
        
    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Bu kullanıcı adı zaten kullanımda.')

class LoginForm(FlaskForm):
    email = StringField('E-posta', validators=[InputRequired(), Length(max=50)])
    password = PasswordField('Parola', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Giriş Yap')


def get_random_question():
    # Tüm soruları çek
    all_questions = Question.query.all()

    # Kullanıcının daha önce cevapladığı soruları al
    answered_question_ids = [answer.question_id for answer in current_user.answers]

    # Cevaplanmamış soruları filtrele
    unanswered_questions = [question for question in all_questions if question.id not in answered_question_ids]

    # Eğer cevaplanmamış soru varsa, rastgele birini seç
    if unanswered_questions:
        return choice(unanswered_questions)
    else:
        return None
    

admin = Admin(app)
admin.add_view(ModelView(Question, db.session))


class ExamForm(FlaskForm):
    answer = RadioField('Cevabınız', choices=[], validators=[InputRequired()])
    submit = SubmitField('Cevabı Gönder')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class AddQuestionForm(FlaskForm):
    content = StringField('Soru İçeriği', validators=[InputRequired()])
    correct_answer = StringField('Doğru Cevap', validators=[InputRequired()])
    incorrect_answers = StringField('Yanlış Cevaplar (Virgülle Ayırın)', validators=[InputRequired()])
    points = IntegerField('Puan', validators=[InputRequired()])
    submit = SubmitField('Soruyu Ekle')

@app.route('/add_question', methods=['GET', 'POST'])
@login_required
def add_question():

    form = AddQuestionForm()

    if form.validate_on_submit():
        # Formdan gelen verileri al
        content = form.content.data
        correct_answer = form.correct_answer.data
        incorrect_answers = form.incorrect_answers.data.split(',')
        points = form.points.data

        # Soruyu veritabanına ekle
        db_question = Question(
            content=content,
            correct_answer=correct_answer,
            incorrect_answers=','.join(incorrect_answers),
            points=points
        )
        db.session.add(db_question)
        db.session.commit()

        flash('Soru başarıyla eklendi!', 'success')
        return redirect(url_for('add_question'))

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/weather', methods=['POST'])
def weather():
    city = request.form['city']
    url = f"http://api.openweathermap.org/data/2.5/weather?q={city}&appid={apiKey}&units=metric"
    response = requests.get(url)
    weather_data = response.json()

    if response.status_code == 200:
        weather = {
            'description': weather_data['weather'][0]['description'],
            'temperature': weather_data['main']['temp'],
            'city': weather_data['name'],
            'country': weather_data['sys']['country']
        }
        return render_template('weather.html', weather=weather)
    else:
        flash("Böyle bir şehir bulunamadı.","danger")
        return redirect(url_for("index"))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Kullanıcıyı veritabanına ekle
        user = User(username=form.username.data, email=form.email.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()

        # Kullanıcıyı oturum açmış olarak işaretle
        login_user(user)

        flash('Kayıt başarılı!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Giriş başarılı!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Giriş başarısız. Lütfen e-posta ve şifrenizi kontrol edin.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required  # Bu, sadece oturumu açık olan kullanıcıların çıkış yapabilmesini sağlar
def logout():
    logout_user()
    flash('Çıkış yapıldı.', 'success')
    return redirect(url_for('index'))


@app.route('/exam')
@login_required
def exam():
    for message, category in get_flashed_messages(with_categories=True):
        pass

    question = get_random_question_from_db()
    if question:
        current_user.last_question = question
        db.session.commit()
        return render_template('exam.html', question=question, form=ExamForm())
    else:
        flash('Sorular çekilemedi ya da tüm soruları cevapladınız.', 'danger')
        return redirect(url_for('index'))




@app.route('/submit_answer', methods=['POST'])
@login_required
def submit_answer():
    form = ExamForm()

    if form.validate_on_submit():
        user_answer = form.answer.data

        # Answer modeline kaydet
        answer = Answer(
            user=current_user,
            question=current_user.last_question,
            user_answer=user_answer
        )
        db.session.add(answer)

        if user_answer == current_user.last_question.correct_answer:
            current_user.score += current_user.last_question.points
            flash('Doğru cevap! Puanınız artırıldı.', 'success')
        else:
            current_user.score -= 5
            flash('Yanlış cevap. Puanınız 5 azaltıldı.', 'danger')

        # Son soruyu güncelle
        current_user.last_question = get_random_question_from_db()

        # Puanı güncelle
        db.session.commit()

        flash('Cevabınız gönderildi!', 'success')

    return redirect(url_for('exam'))



@app.route('/leaderboard')
@login_required
def leaderboard():
    return render_template('leaderboard.html', user=current_user)

def get_random_question_from_db():
    return Question.query.filter(and_(Question.id != current_user.last_question_id, Question.id.notin_([q.id for q in current_user.answers]))).order_by(func.random()).first()


if __name__ == '__main__':
    app.run(debug=True)
