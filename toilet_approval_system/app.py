import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.pool import StaticPool
from functools import wraps

app = Flask(__name__)

# 从环境变量获取配置，如果没有则使用默认值
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')

# 获取数据库URL，Render会自动提供DATABASE_URL环境变量
database_url = os.environ.get('DATABASE_URL', 'sqlite:///toilet_approval.db')

# 如果使用 PostgreSQL（Render免费提供），需要调整URI格式
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'poolclass': StaticPool,
    'connect_args': {'check_same_thread': False}
}

db = SQLAlchemy(app)



# 用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'A', 'B'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)  # 修改为 'active' 列

    # Flask-Login 需要的属性和方法
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return self.active  # 返回 active 列的值

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def is_admin(self):
        return self.role == 'admin'


# 上厕所申请模型
class ToiletRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.String(500))
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected, cancelled
    apply_time = db.Column(db.DateTime, default=datetime.utcnow)
    approve_time = db.Column(db.DateTime)
    notes = db.Column(db.String(500))

    def __repr__(self):
        return f'<ToiletRequest {self.id} - {self.status}>'

    def get_status_text(self):
        status_map = {
            'pending': '待审批',
            'approved': '已批准',
            'rejected': '已拒绝',
            'cancelled': '已取消',
            'approve': '已批准',
            'reject': '已拒绝'
        }
        return status_map.get(self.status, self.status)

    @property
    def status_cn(self):
        return self.get_status_text()

    def get_applicant(self):
        return User.query.get(self.applicant_id)

    def get_approver(self):
        return User.query.get(self.approver_id)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# 权限装饰器
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_admin():
            flash('需要管理员权限才能访问此页面！', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return decorated_function


# 创建数据库表
with app.app_context():
    db.create_all()
    # 创建默认用户（如果不存在）
    if not User.query.filter_by(username='A').first():
        user_a = User(
            username='A',
            password=generate_password_hash('passwordA'),
            role='A',
            active=True  # 修改为 active
        )
        user_b = User(
            username='B',
            password=generate_password_hash('passwordB'),
            role='B',
            active=True  # 修改为 active
        )
        db.session.add(user_a)
        db.session.add(user_b)

    # 创建默认管理员用户（如果不存在）
    if not User.query.filter_by(role='admin').first():
        admin_user = User(
            username='admin',
            password=generate_password_hash('admin123'),
            role='admin',
            active=True  # 修改为 active
        )
        db.session.add(admin_user)

    db.session.commit()


# 上下文处理器 - 添加状态转换函数到模板中
@app.context_processor
def inject_models():
    def get_status_chinese(status):
        status_map = {
            'pending': '待审批',
            'approved': '已批准',
            'rejected': '已拒绝',
            'cancelled': '已取消',
            'approve': '已批准',
            'reject': '已拒绝'
        }
        return status_map.get(status, status)

    return dict(get_status_chinese=get_status_chinese, User=User)


# 路由定义
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('请输入用户名和密码！', 'danger')
            return render_template('login.html')

        user = User.query.filter_by(username=username, active=True).first()  # 修改为 active

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f'欢迎回来，{user.username}！', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('用户名或密码错误！', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功退出登录！', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    # 获取统计数据
    total_requests = ToiletRequest.query.filter_by(applicant_id=current_user.id).count()
    pending_requests = ToiletRequest.query.filter_by(
        applicant_id=current_user.id,
        status='pending'
    ).count()

    # 获取待审批的申请（别人提交给我审批的）
    requests_to_approve = ToiletRequest.query.filter_by(
        approver_id=current_user.id,
        status='pending'
    ).order_by(ToiletRequest.apply_time.desc()).limit(5).all()

    # 获取我最近提交的申请
    my_recent_requests = ToiletRequest.query.filter_by(
        applicant_id=current_user.id
    ).order_by(ToiletRequest.apply_time.desc()).limit(5).all()

    return render_template('dashboard.html',
                           total_requests=total_requests,
                           pending_requests=pending_requests,
                           requests_to_approve=requests_to_approve,
                           my_recent_requests=my_recent_requests)


# 修改密码 - 所有用户都可以修改自己的密码
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # 验证输入
        if not current_password or not new_password or not confirm_password:
            flash('请填写所有字段！', 'danger')
            return render_template('change_password.html')

        if new_password != confirm_password:
            flash('新密码和确认密码不一致！', 'danger')
            return render_template('change_password.html')

        # 验证当前密码
        if not check_password_hash(current_user.password, current_password):
            flash('当前密码错误！', 'danger')
            return render_template('change_password.html')

        # 更新密码
        current_user.password = generate_password_hash(new_password)
        db.session.commit()

        flash('密码修改成功！', 'success')
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')


# 管理员功能：用户管理
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    # 获取所有用户
    users = User.query.order_by(User.role, User.username).all()
    return render_template('admin_users.html', users=users)


# 管理员功能：编辑用户
@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    # 防止管理员编辑自己时出现权限问题（这里允许，但可以特殊处理）
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update':
            # 更新用户信息
            username = request.form.get('username')
            role = request.form.get('role')
            new_password = request.form.get('new_password')
            active = request.form.get('active') == 'on'  # 修改为 active

            # 检查用户名是否已存在（排除当前用户）
            existing_user = User.query.filter(User.username == username, User.id != user.id).first()
            if existing_user:
                flash('用户名已存在！', 'danger')
                return render_template('edit_user.html', user=user)

            # 更新用户信息
            user.username = username
            user.role = role
            user.active = active  # 修改为 active

            # 如果提供了新密码，则更新
            if new_password:
                user.password = generate_password_hash(new_password)

            db.session.commit()
            flash('用户信息更新成功！', 'success')
            return redirect(url_for('admin_users'))

        elif action == 'delete':
            # 删除用户（软删除，设置为非活跃）
            user.active = False  # 修改为 active
            db.session.commit()
            flash(f'用户 {user.username} 已禁用！', 'info')
            return redirect(url_for('admin_users'))

    return render_template('edit_user.html', user=user)


# 管理员功能：创建新用户
@app.route('/admin/user/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')

        # 验证输入
        if not username or not password:
            flash('请填写用户名和密码！', 'danger')
            return render_template('create_user.html')

        if password != confirm_password:
            flash('密码和确认密码不一致！', 'danger')
            return render_template('create_user.html')

        # 检查用户名是否已存在
        if User.query.filter_by(username=username).first():
            flash('用户名已存在！', 'danger')
            return render_template('create_user.html')

        # 创建新用户
        new_user = User(
            username=username,
            password=generate_password_hash(password),
            role=role,
            active=True  # 修改为 active
        )

        db.session.add(new_user)
        db.session.commit()

        flash(f'用户 {username} 创建成功！', 'success')
        return redirect(url_for('admin_users'))

    return render_template('create_user.html')


# 管理员功能：重置用户密码（无需旧密码）
@app.route('/admin/user/<int:user_id>/reset_password', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('请填写所有字段！', 'danger')
            return render_template('admin_reset_password.html', user=user)

        if new_password != confirm_password:
            flash('新密码和确认密码不一致！', 'danger')
            return render_template('admin_reset_password.html', user=user)

        # 重置密码
        user.password = generate_password_hash(new_password)
        db.session.commit()

        flash(f'用户 {user.username} 的密码已重置！', 'success')
        return redirect(url_for('admin_users'))

    return render_template('admin_reset_password.html', user=user)


# 原有的申请相关路由（保持不变）
@app.route('/submit_request', methods=['GET', 'POST'])
@login_required
def submit_request():
    if request.method == 'POST':
        reason = request.form.get('reason')
        urgency = request.form.get('urgency', 'normal')

        if not reason:
            flash('请填写上厕所原因！', 'danger')
            return render_template('submit_request.html')

        # 根据规则确定审批人：A的申请由B审批，B的申请由A审批
        approver_role = 'B' if current_user.role == 'A' else 'A'
        approver = User.query.filter_by(role=approver_role, active=True).first()  # 修改为 active

        if not approver:
            flash('找不到合适的审批人！', 'danger')
            return redirect(url_for('dashboard'))

        # 创建申请
        toilet_request = ToiletRequest(
            applicant_id=current_user.id,
            approver_id=approver.id,
            reason=reason,
            status='pending'
        )

        db.session.add(toilet_request)
        db.session.commit()

        flash(f'上厕所申请已提交！将由 {approver.username} 审批。', 'success')
        return redirect(url_for('view_my_requests'))

    return render_template('submit_request.html')


@app.route('/view_my_requests')
@login_required
def view_my_requests():
    page = request.args.get('page', 1, type=int)
    requests = ToiletRequest.query.filter_by(applicant_id=current_user.id) \
        .order_by(ToiletRequest.apply_time.desc()) \
        .paginate(page=page, per_page=10)

    return render_template('view_requests.html',
                           requests=requests,
                           title='我的申请记录',
                           show_actions=True)


@app.route('/view_requests_to_approve')
@login_required
def view_requests_to_approve():
    page = request.args.get('page', 1, type=int)
    requests = ToiletRequest.query.filter_by(
        approver_id=current_user.id,
        status='pending'
    ).order_by(ToiletRequest.apply_time.desc()) \
        .paginate(page=page, per_page=10)

    return render_template('view_requests.html',
                           requests=requests,
                           title='待审批申请',
                           show_approval_actions=True)


@app.route('/approve_request/<int:request_id>', methods=['GET', 'POST'])
@login_required
def approve_request(request_id):
    toilet_request = ToiletRequest.query.get_or_404(request_id)

    if toilet_request.approver_id != current_user.id:
        flash('您没有权限审批此申请！', 'danger')
        return redirect(url_for('dashboard'))

    if toilet_request.status != 'pending':
        flash('此申请已处理，无法再次审批！', 'warning')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        decision = request.form.get('decision')
        notes = request.form.get('notes', '')

        if not decision or decision not in ['approve', 'reject']:
            flash('请选择审批决定！', 'danger')
            return redirect(url_for('approve_request', request_id=request_id))

        if decision == 'approve':
            toilet_request.status = 'approved'
        else:
            toilet_request.status = 'rejected'

        toilet_request.notes = notes
        toilet_request.approve_time = datetime.utcnow()

        db.session.commit()

        action_text = '批准' if decision == 'approve' else '拒绝'
        flash(f'已{action_text}上厕所申请！', 'success')
        return redirect(url_for('view_requests_to_approve'))

    applicant = toilet_request.get_applicant()

    return render_template('approve_request.html',
                           request=toilet_request,
                           applicant=applicant)


@app.route('/cancel_request/<int:request_id>')
@login_required
def cancel_request(request_id):
    toilet_request = ToiletRequest.query.get_or_404(request_id)

    if toilet_request.applicant_id != current_user.id:
        flash('您只能取消自己的申请！', 'danger')
        return redirect(url_for('view_my_requests'))

    if toilet_request.status != 'pending':
        flash('只有待审批的申请才能取消！', 'warning')
        return redirect(url_for('view_my_requests'))

    toilet_request.status = 'cancelled'
    db.session.commit()

    flash('申请已取消！', 'info')
    return redirect(url_for('view_my_requests'))


@app.route('/request_details/<int:request_id>')
@login_required
def request_details(request_id):
    toilet_request = ToiletRequest.query.get_or_404(request_id)

    if toilet_request.applicant_id != current_user.id and toilet_request.approver_id != current_user.id:
        flash('您没有权限查看此申请！', 'danger')
        return redirect(url_for('dashboard'))

    applicant = toilet_request.get_applicant()
    approver = toilet_request.get_approver()

    return render_template('request_details.html',
                           request=toilet_request,
                           applicant=applicant,
                           approver=approver)


@app.route('/api/stats')
@login_required
def get_stats():
    total = ToiletRequest.query.filter_by(applicant_id=current_user.id).count()
    approved = ToiletRequest.query.filter_by(applicant_id=current_user.id, status='approved').count()
    rejected = ToiletRequest.query.filter_by(applicant_id=current_user.id, status='rejected').count()
    pending = ToiletRequest.query.filter_by(applicant_id=current_user.id, status='pending').count()

    return jsonify({
        'total': total,
        'approved': approved,
        'rejected': rejected,
        'pending': pending
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)  # 确保debug=False