#coding=utf-8
import os
from flask import Flask, render_template, session, redirect, \
				  url_for, flash, current_app, request
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, LoginManager, login_required, \
						login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, \
					BooleanField, IntegerField, ValidationError
from wtforms.validators import Required, Length, Regexp
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy import event
'''
Config
'''
basedir = os.path.abspath(os.path.dirname(__file__))


def make_shell_context():
	return dict(app=app, db=db, User=User, Role=Role)


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://ownxl:1234..xl@192.168.71.129:11111/test'
	

app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['AdminPassword'] = 111111
app.config['SECRET_KEY'] = "this is a secret_key"
db = SQLAlchemy(app)
manager = Manager(app)
bootstrap = Bootstrap(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)
manager.add_command('shell', Shell(make_shell_context))
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.login_message = u"你需要登录才能访问这个页面."


'''
Models
'''
class Role(db.Model):
	__tablename__ = 'roles'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64), unique=True)
	users = db.relationship('User', backref='role', lazy='dynamic')

	@staticmethod
	def insert_roles():
		PGDialect._get_server_version_info = lambda *args: (9, 2)
		roles = ('Adminlevel0','Admin')
		for r in roles:
			role = Role.query.filter_by(name=r).first()
			if role is None:
				role = Role(name=r)
			db.session.add(role)
		db.session.commit()


	def __repr__(self):
		PGDialect._get_server_version_info = lambda *args: (9, 2)
		return '<Role %r>' %self.name

class User(UserMixin, db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	number = db.Column(db.SmallInteger, unique=True, index=True)
	username = db.Column(db.String(64), index=True)
	password = db.Column(db.String(128), default=123456)
	role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
	
	def __init__(self, **kwargs):
		PGDialect._get_server_version_info = lambda *args: (9, 2)
		super(User, self).__init__(**kwargs)
		#新添加的用户，初始其角色为学生。
		if self.role is None:
			self.role = Role.query.filter_by(name='Adminlever0').first()

	def __repr__(self):
		PGDialect._get_server_version_info = lambda *args: (9, 2)
		return '<User %r>' %self.username

	#初次运行程序时生成初始管理员的静态方法
	@staticmethod
	def generate_admin():
		PGDialect._get_server_version_info = lambda *args: (9, 2)
		admin = Role.query.filter_by(name='Admin').first()
		u = User.query.filter_by(role=admin).first()
		if u is None:
			u = User(number = 000000, username = 'Admin',\
					 password = current_app.config['AdminPassword'],\
					 role = Role.query.filter_by(name='Admin').first())
			db.session.add(u)
		db.session.commit()

	def verify_password(self, password):
		PGDialect._get_server_version_info = lambda *args: (9, 2)
		return self.password == password

class Material(db.Model):
	__tablename__ = 'materials'
	id = db.Column(db.Integer, primary_key=True)
	number = db.Column(db.String(64), unique=True, index=True)
	type = db.Column(db.String(64), index=True)
	state = db.Column(db.String(64))
	name = db.Column(db.String(64))
	manufacture = db.relationship('Manufacture', backref='material', lazy='dynamic')

	def __init__(self, **kwargs):
		PGDialect._get_server_version_info = lambda *args: (9, 2)
		super(Material, self).__init__(**kwargs)

	@staticmethod
	def insert_material():
		PGDialect._get_server_version_info = lambda *args: (9, 2)
		materials = ('base1','base2')
		for m in materials:
			material = Material.query.filter_by(typy=m).first()
			if material is None:
				material = Material(type=m)
			db.session.add(material)
		db.session.commit()


	def __repr__(self):
		PGDialect._get_server_version_info = lambda *args: (9, 2)
		return '<Material %r>' %self.name
	
class Manufacture(db.Model):
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	__tablename__ = 'manufacture'
	id = db.Column(db.Integer, primary_key=True)
	numworkshop = db.Column(db.String(64))
	upon = db.Column(db.String(64))
	down = db.Column(db.String(64))
	material_num = db.Column(db.String(64), db.ForeignKey('materials.number'))


	def __repr__(self):
		PGDialect._get_server_version_info = lambda *args: (9, 2)
		return '<Manufacture %r>' %self.name


'''
Forms
'''
class LoginForm(FlaskForm):
	number = StringField(u'账号', validators=[Required()])
	password = PasswordField(u'密码', validators=[Required()])
	remember_me = BooleanField(u'记住我')
	submit = SubmitField(u'登录')

class SelectForm(FlaskForm):
	name1check = BooleanField(u'Material')
	name2check = BooleanField(u'Manufacture')
	submit = SubmitField(u'确认选择')

class SearchForm(FlaskForm):
	number = StringField(u'编号', validators=[Required()])
	submit = SubmitField(u'搜索')

class Search2Form(FlaskForm):
	id = IntegerField(u'ID',validators=[Required(message=u'请输入数字')])
	submit = SubmitField(u'搜索')

class MaterialForm(FlaskForm):
	
	id = IntegerField(u'ID', validators=[Required(message=u'请输入数字')])
	type = StringField(u'种类', validators=[Required()])
	number = StringField(u'编号', validators=[Required()])
	name = StringField(u'名称', validators=[Required()])
	state = StringField(u'质量', validators=[Required()])
	submit = SubmitField(u'添加')

	def validate_id(self, field):
		if Material.query.filter_by(id=field.data).first():
			raise ValidationError(u'此物料已记录，请检查ID！')
		
	def validate_number(self, field):
		if Material.query.filter_by(number=field.data).first():
			raise ValidationError(u'此物料已记录，请检查编号！')
	
class ManufForm(FlaskForm):
	id = IntegerField(u'ID', validators=[Required(message=u'请输入数字')])
	materialnum = StringField(u'物料编号', validators=[Required()])
	numworkshop = StringField(u'工作车间', validators=[Required()])
	upon = StringField(u'上级物料编号', validators=[Required()])
	down = StringField(u'下级物料编号', validators=[Required()])
	submit = SubmitField(u'添加')

	def validate_id(self, field):
		if Manufacture.query.filter_by(id=field.data).first():
			raise ValidationError(u'已存在，请检查ID！')

	def validate_materialnum(self, field):
		if Material.query.filter_by(number=field.data).first() == None:
			raise ValidationError(u'此物料未记录，请检查编号！')
	
	def validate_upon(self, field):
		if Material.query.filter_by(number=field.data).first() == None and field.data != '无':
			raise ValidationError(u'此物料未记录，请检查编号！')
	 
	def validate_down(self, field):
		if Material.query.filter_by(number=field.data).first() == None and field.data != '无':
			raise ValidationError(u'此物料未记录，请检查编号！')

class EditForm(FlaskForm):
	type = StringField(u'种类', validators=[Required()])
	number = StringField(u'编号', validators=[Required()])
	name = StringField(u'名称', validators=[Required()])
	state = StringField(u'状态', validators=[Required()])
	submit = SubmitField(u'修改')

	def __init__(self, material, *args, **kargs):
		super(EditForm, self).__init__(*args, **kargs)
		self.material = material

	def validate_number(self, field):
		if field.data != self.material.number and \
				Material.query.filter_by(number=field.data).first():
			raise ValidationError(u'已存在，请重新输入！')

class EditmanufForm(FlaskForm):

	materialnum = StringField(u'物料编号', validators=[Required()])
	numworkshop = StringField(u'工作车间', validators=[Required()])
	upon = StringField(u'上级物料编号', validators=[Required()])
	down = StringField(u'下级物料编号', validators=[Required()])
	
	submit = SubmitField(u'修改')

	def __init__(self, manufacture, *args, **kargs):
		super(EditmanufForm, self).__init__(*args, **kargs)
		self.manufacture = manufacture

	def validate_id(self, field):
		if field.data != self.manufacture.id and \
				Manufacture.query.filter_by(id=field.data).first():
			raise ValidationError(u'已存在，请重新输入！')
	
	def validate_materialnum(self, field):
		if Material.query.filter_by(number=field.data).first() == None:
			raise ValidationError(u'此物料未记录，请检编号！')
	
	def validate_upon(self, field):
		if Material.query.filter_by(number=field.data).first() == None and field.data != '无':
			raise ValidationError(u'此物料未记录，请检查编号！')

	def validate_down(self, field):
		if Material.query.filter_by(number=field.data).first() == None and field.data != '无':
			raise ValidationError(u'此物料未记录，请检查编号！')

'''
views
'''
@app.route('/', methods=['GET', 'POST'])
@login_required
def indexall():
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	form = SelectForm()
	if form.validate_on_submit():
		if form.name1check.data == form.name2check.data:
			return render_template('erroreturn.html')
		elif form.name1check.data == True:
			return redirect(url_for('index'))
		elif form.name2check.data == True:
			return redirect(url_for('index2'))
		
	else:	
		return render_template('indexall.html',form=form)
		
@app.route('/index',methods=['GET','POST'])
@login_required
def index():
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	form = SearchForm()
	if form.validate_on_submit():
		#获得列表，其编号包含form中的数字
		materialall = Material.query.filter(Material.number.like \
								('%{}%'.format(form.number.data))).all()
	else:
		materialall = Material.query.order_by(Material.number.asc()).all()
	return render_template('index.html', form=form, materials=materialall)

@app.route('/index2',methods=['GET','POST'])
@login_required
def index2():
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	form = SearchForm()
	form2 = Search2Form()
	if form.validate_on_submit():
		#获得列表，其编号包含form中的数字
		manufactureall = Manufacture.query.filter(Manufacture.id.like \
								('%{}%'.format(form.number.data))).all()
		return render_template('indexcopy.html', form=form, form2=form2, manufactures=manufactureall)
	elif form2.validate_on_submit():
		manufactureall = Manufacture.query.filter_by(id=form2.id.data).first()
		material = Material.query.filter(Material.number == manufactureall.material_num)
		return render_template('index2.html', materials=material)
	else:
		manufactureall = Manufacture.query.order_by(Manufacture.id.asc()).all()
		return render_template('indexcopy.html', form=form, form2=form2, manufactures=manufactureall)

#增加
@app.route('/add-material', methods=['GET', 'POST'])
@login_required
def add_material():
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	form = MaterialForm()
	if form.validate_on_submit():
		materialadd = Material(id=form.id.data,
					type=form.type.data,
					number=form.number.data,
					name=form.name.data,
					state=form.state.data)
		db.session.add(materialadd)
		flash(u'成功添加!')
		return redirect(url_for('index'))
	return render_template('add.html', form=form)

@app.route('/add-manuf', methods=['GET', 'POST'])
@login_required
def add_manuf():
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	form = ManufForm()
	if form.validate_on_submit():
		manufadd = Manufacture(id=form.id.data,
					material_num=form.materialnum.data,
					numworkshop=form.numworkshop.data,
					upon=form.upon.data,
					down=form.down.data)
		db.session.add(manufadd)
		flash(u'成功添加!')
		return redirect(url_for('index2'))
	return render_template('add.html', form=form)

#删除
@app.route('/remove-material/<int:id>', methods=['GET', 'POST'])
@login_required
def remove_material(id):
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	materialrm = Material.query.get_or_404(id)
	Manufacture.query.filter(Manufacture.material_num == materialrm.number ).delete()
	Manufacture.query.filter(Manufacture.upon == materialrm.number).delete()
	Manufacture.query.filter(Manufacture.down == materialrm.number).delete()
	db.session.delete(materialrm)
	flash(u'成功删除！')
	return redirect(url_for('index'))

@app.route('/remove-manuf/<int:id>', methods=['GET', 'POST'])
@login_required
def remove_manuf(id):
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	manufrm = Manufacture.query.filter_by(id=id).first()
	db.session.delete(manufrm)
	flash(u'成功删除！')
	return redirect(url_for('index2'))

#修改资料
@app.route('/edit-material/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_material(id):
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	materialedit = Material.query.get_or_404(id)
	form = EditForm(material= materialedit)
	if form.validate_on_submit():
		materialedit.type = form.type.data
		materialedit.number = form.number.data
		materialedit.name = form.name.data
		materialedit.state = form.state.data
		db.session.add(materialedit)
		flash(u'信息已更改')
		return redirect(url_for('index'))
	form.type.data = materialedit.type
	form.number.data = materialedit.number
	form.name.data = materialedit.name
	form.state.data = materialedit.state
	return render_template('edit.html', form=form, material=materialedit)

@app.route('/edit-manuf/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_manuf(id):
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	manufedit = Manufacture.query.get_or_404(id)
	form = EditmanufForm(manufacture= manufedit)
	if form.validate_on_submit():
		manufedit.material_num = form.materialnum.data
		manufedit.numworkshop = form.numworkshop.data
		manufedit.upon = form.upon.data
		manufedit.down = form.down.data
		db.session.add(manufedit)
		flash(u'信息已更改')
		return redirect(url_for('index2'))
	form.materialnum.data = manufedit.material_num
	form.numworkshop.data = manufedit.numworkshop
	form.upon.data = manufedit.upon
	form.down.data = manufedit.down
	return render_template('edit.html', form=form, manufacture=manufedit)

#登录，系统只允许管理员登录
@app.route('/login', methods=['GET', 'POST'])
def login():
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	form  = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(number=form.number.data).first()
		if user is not None and user.verify_password(form.password.data):
			if user.role != Role.query.filter_by(name='Admin').first():
				flash(u'系统只对管理员开放，请联系管理员获得权限！')
			else:
				login_user(user, form.remember_me.data)
				return redirect(url_for('indexall'))
		flash(u'用户名或密码错误！')
	return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	logout_user()
	flash(u'成功注销！')
	return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
	return render_template('500.html'), 500

#加载用户的回调函数
@login_manager.user_loader
def load_user(user_id):
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	return User.query.get(int(user_id))

'''@event.listens_for(Material,"after_delete")
def deletemanufact(mapper,connection,target):
	PGDialect._get_server_version_info = lambda *args: (9, 2)
	
	Manufacture.query.filter(Manufacture.material_num == '111').delete()
		#db.session.commit()
	#raise ValidationError(u'1')'''

'''
增加命令'python app.py init' 
以增加身份与初始管理员帐号
'''
@manager.command
def init():
	from app import Role, User
	Role.insert_roles()
	User.generate_admin()


if __name__=='__main__':
	manager.run()