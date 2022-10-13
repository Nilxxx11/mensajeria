from flask import Flask, render_template, flash, redirect, url_for, session, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField,TextAreaField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_session import Session
from flask_mail import Mail, Message 
from flask import copy_current_request_context
import threading
import random
from datetime import date, datetime
today = date.today()

#CONFIGURACION:________________
app = Flask(__name__)
app.config['SECRET_KEY'] = 'FHBF64BJK866'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mensajeria.sqlite'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
Session(app)
socketio = SocketIO(app, manage_session=False, cors_allowed_origins="*")
app.config['MAIL_SERVER']='smtp-mail.outlook.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'neilp@uninorte.edu.co'
app.config['MAIL_PASSWORD'] = 'logmein123'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)
###############################################


#MODELOS:_______________________
class User(UserMixin, db.Model):
    __tablename__="USUARIOS"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(15))
    mensaje = db.relationship('Msg')
    fecha=db.Column(db.DateTime, default=today)
    hash = db.Column(db.String(30), unique=True)
    activo = db.Column(db.Integer)
    
    
class Msg(db.Model):
    __tablename__="MENSAJES"
    id_entrada=db.Column(db.Integer, primary_key=True)
    user_remitente=db.Column(db.String)
    uid_destino=db.Column(db.Integer,db.ForeignKey('USUARIOS.id'))
    asunto=db.Column(db.String(80))
    mensaje=db.Column(db.String(300))
    fecha=db.Column(db.DateTime, default=today)
    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#FORMULARIOS:___________________
class LoginForm(FlaskForm):
    username = StringField('usuario', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('contraseña', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('recuerdame')

class RegisterForm(FlaskForm):
    email = StringField('correo electronico', validators=[InputRequired(), Email(message='email invalido'), Length(max=50)])
    username = StringField('usuario', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('contraseña', validators=[InputRequired(), Length(min=8, max=80)])

class MensajesForm(FlaskForm):
    id_destino=StringField('usuario destino',validators=[InputRequired()])
    asunto=StringField('asunto',validators=[InputRequired(), Length(min=1, max=30)])
    mensaje=TextAreaField(u'Escribe el mensaje',validators=[InputRequired(), Length(min=4, max=300)])

#VISTAS:_________________________
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if user.activo==1:
                if check_password_hash(user.password, form.password.data):
                    login_user(user, remember=form.remember.data)
                    return redirect(url_for('dashboard'))
        flash('Usuario-Contraseña incorrectos Ó Cuenta no activa...')
       # return '<h1>Usuario o Contraseña incorrectos, ó Usuario no registrado</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    hash = random.getrandbits(16)
    def send_email(email_destino):
        msg = Message( 
                'REGISTRO EXITOSO A CHAT-GRUPO 5!', 
                sender ='neilp@uninorte.edu.co', recipients = [email_destino] )
        msg.body = 'ACTIVA TU CUENTA: http://7889-191-69-110-93.ngrok.io/activacion/'+str(hash)
        mail.send(msg)
        
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, hash=hash, activo=0)
        email_destino=form.email.data
        user = User.query.filter_by(email=email_destino).first()
        if not user:
            db.session.add(new_user)
            db.session.commit()
            @copy_current_request_context
            def send_menssage(email_destino):
                send_email(email_destino)
            enviar=threading.Thread(name='enviar',target=send_menssage,args=(email_destino,))
            enviar.start()
            flash("Registro Exitoso... Activa tu cuenta por el Email!")
        flash("Email ya existe en la base de datos...")

    return render_template('signup.html', form=form)

@app.route('/activacion/<hash>')
def activacion_user(hash):
    user = User.query.filter_by(hash=hash).first()
    print (user)
    if user:
        user.activo=1
        db.session.add(user)
        db.session.commit()
        return render_template('activado.html')
    return render_template('index.html')
 
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)
    
@app.route('/perfil')
@login_required
def perfil():
    return render_template('perfil_usuario.html', name=current_user.username, email=current_user.email,fecha=current_user.fecha)
    
@app.route('/configuracion')
@login_required
def configuracion():
    return render_template('configuracion.html', name=current_user.username, email=current_user.email,fecha=current_user.fecha)

"""te('/restablecer')
@login_required
def restablecer():
    @copy_current_request_context
            def send_menssage(cu:
                send_email(email_destino)
            enviar=threading.Thread(name='enviar',target=send_menssage,args=(email_destino,))
            enviar.start()
    return redirect(url_for('dasboard'))
"""


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
    

    
#CHAT________________
#iniciat chat
@login_required
@app.route('/inicio/chat', methods=['GET', 'POST'])
def inicio_chat():
    return render_template('inicio_chat.html')

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    
    username = current_user.username
    room = "MisionTic 2022"
        
    session['username'] = username
    session['room'] = room
    return render_template('chat.html', session = session)

    if(session.get('username') is not None):
        return render_template('chat.html', session = session)
    else:
        return redirect(url_for('index'))

   
#indicar quienes ingresan al chat
@socketio.on('join', namespace='/chat')
def join(message):
    room = session.get('room')
    join_room(room)
    emit('status', {'msg':  session.get('username') + ' Inicio sesion.'}, room=room)

#agregar los mesajes enviados
@socketio.on('text', namespace='/chat')
def text(message):
    room = session.get('room')
    emit('message', {'msg': session.get('username') + ' : ' + message['msg']}, room=room)

#quienes salen del chat
@socketio.on('left', namespace='/chat')
def left(message):
    room = session.get('room')
    username = session.get('username')
    leave_room(room)
    session.clear()
    emit('status', {'msg': username + ' Salio del chat.'}, room=room)

######################################
@app.route('/mensaje', methods=['GET', 'POST'])
def mensaje():
    users=User.query.all()
    
    
    return render_template('mensaje.html',users=users)
    
@app.route('/mensaje/enviar/<id>', methods=['GET', 'POST'])
def enviar(id):
    form = MensajesForm()
    user=User.query.get(id)
    if form.validate_on_submit():
        
        new_msg = Msg(user_remitente=current_user.username, uid_destino=form.id_destino.data, asunto=form.asunto.data, mensaje=form.mensaje.data,fecha=today)
        db.session.add(new_msg)
        db.session.commit()
        flash("MENSAJE ENVIADO")
    return render_template('enviar.html',user=user,form=form)
    
@app.route('/mensaje/entrada', methods=['GET', 'POST'])
def entrada():
    msgs=Msg.query.filter_by(uid_destino=current_user.username)
    return render_template('entrada.html',msgs=msgs)
    
#INICIAR APP:___________________
if __name__ == '__main__':
    app.run(debug=True, port=5000)
