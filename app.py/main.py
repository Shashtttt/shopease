from wsgiref.validate import validator
from flask_wtf.csrf import CSRFProtect
from flask import Flask, render_template, redirect, url_for, flash, request, session as flask_session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, IntegerField, TextAreaField, FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from werkzeug.utils import secure_filename
import stripe
import os
import shutil
from datetime import datetime, timedelta
from functools import wraps
from wtforms import BooleanField


app = Flask(__name__, template_folder='template', static_folder='static')
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://myuser:newpassword@localhost/shopease'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# IMPORTANT: Path configuration for the image upload fix
# This is where the uploaded files are being saved
CURRENT_UPLOAD_PATH = 'path/to/where/files/are/currently/saved'  # Update this!

# This is where the template is looking for the files
CORRECT_UPLOAD_PATH = 'static/uploads'  # This matches your template path

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Stripe setup
stripe.api_key = 'your_stripe_secret_key_here'
ADMIN_SECRET_CODE = os.getenv('ADMIN_CODE', 'admin123')

csrf = CSRFProtect(app)
# Add this near the top of your file, after app = Flask(...)
app.config['WTF_CSRF_ENABLED'] = False
# Context processor for current time
@app.context_processor
def inject_now():
    return {'now': datetime.now()}


@app.route('/api/placeholder/<int:width>/<int:height>')
def placeholder_image(width, height):
    # Return a generated placeholder image
    return f"Placeholder image of size {width}x{height}"


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    # Define relationships with cascade delete
    cart_items = db.relationship('CartItem', backref='user',
                                 cascade='all, delete-orphan',
                                 foreign_keys='CartItem.user_id')
    orders = db.relationship('Order', backref='user',
                             cascade='all, delete-orphan',
                             foreign_keys='Order.user_id',
                             primaryjoin='User.id == Order.user_id')


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    dimensions = db.Column(db.String(20), nullable=False)
    image_url = db.Column(db.String(120), nullable=False, default='default.jpg')

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    is_admin = BooleanField('Register as Admin')  # Added admin checkbox
    admin_code = StringField('Admin Code')  # Optional admin code for validation
    name = StringField('Full Name', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Username already exists!')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Email already registered!')

    def validate_admin_code(self, admin_code):
        if self.is_admin.data and admin_code.data != ADMIN_SECRET_CODE:
            raise ValidationError('Invalid admin code')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])
    category = StringField('Category', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    stock = IntegerField('Stock', validators=[DataRequired()])
    dimensions = StringField('Dimensions', validators=[])
    image = FileField('Product Image')
    featured = BooleanField('Featured Product')
    submit = SubmitField('Save')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def save_product_image(form_image):
    if form_image:
        filename = secure_filename(form_image.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        form_image.save(filepath)
        return filename
    return 'default.jpg'

def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need admin privileges to access this page.', 'danger')
            return redirect(url_for('home'))
        return func(*args, **kwargs)
    return decorated_view

def fix_product_image_urls():
    """Update product image_url values if they contain incorrect paths"""
    updated_count = 0

    for product in Product.query.all():
        image_url = product.image_url

        # If image_url contains a path instead of just the filename
        if '/' in image_url or '\\' in image_url:
            # Extract just the filename
            filename = os.path.basename(image_url)
            product.image_url = filename
            updated_count += 1

    db.session.commit()
    return updated_count
@app.route('/')
def home():
    products = Product.query.all()
    return render_template('home.html', products=products)
@app.route('/about')
def about():
    return render_template('about.html')
@app.route('/contact')
def contact():
    return render_template('contact.html')
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        is_admin = form.is_admin.data and form.admin_code.data == ADMIN_SECRET_CODE

        # Use password_hash instead of password
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_pw,
            is_admin=is_admin,
            name=form.name.data
        )

        db.session.add(user)
        db.session.commit()

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form, title='Register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # Redirect to the appropriate page based on admin status
        if current_user.is_admin:
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # Update this line to use password_hash instead of password
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')

            # Redirect based on user type
            if user.is_admin:
                return redirect(next_page or url_for('dashboard'))
            else:
                return redirect(next_page or url_for('home'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    return render_template('login.html', form=form, title='Login')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/dashboard')
@login_required
@admin_required
def dashboard():
    # Get data for dashboard charts and stats
    products = Product.query.all()
    total_products = Product.query.count()
    total_users = User.query.count()
    total_orders = Order.query.count()

    # Get low stock products (less than 10 items)
    low_stock_products = Product.query.filter(Product.stock < 10).all()

    # Recent orders for display
    recent_orders = Order.query.order_by(Order.date.desc()).limit(5).all()

    # Revenue data for charts
    total_revenue = db.session.query(db.func.sum(Order.total_price)).scalar() or 0

    # Data for revenue chart - last 7 days
    revenue_chart_labels = []
    revenue_chart_data = []
    for i in range(6, -1, -1):
        date = datetime.utcnow() - timedelta(days=i)
        date_str = date.strftime("%Y-%m-%d")
        revenue_chart_labels.append(date.strftime("%a"))

        # Calculate revenue for this day
        day_revenue = db.session.query(db.func.sum(Order.total_price)) \
                          .filter(db.func.date(Order.date) == date.date()).scalar() or 0
        revenue_chart_data.append(float(day_revenue))

    # Data for category chart
    category_chart_labels = []
    category_chart_data = []
    categories = db.session.query(Product.category, db.func.count(Product.id)) \
        .group_by(Product.category).all()

    for category, count in categories:
        category_chart_labels.append(category)
        category_chart_data.append(count)

    # Weekly cart items data
    one_week_ago = datetime.utcnow() - timedelta(days=7)
    weekly_cart_items = (
        db.session.query(
            Product.name,
            db.func.sum(CartItem.quantity).label('total_quantity')
        )
        .join(CartItem, Product.id == CartItem.product_id)
        .filter(CartItem.date_added >= one_week_ago)
        .group_by(Product.name)
        .all()
    )

    return render_template('dashboard.html',
                           products=products,
                           total_products=total_products,
                           total_users=total_users,
                           total_orders=total_orders,
                           total_revenue=total_revenue,
                           weekly_cart_items=weekly_cart_items,
                           recent_orders=recent_orders,
                           low_stock_products=low_stock_products,
                           revenue_chart_labels=revenue_chart_labels,
                           revenue_chart_data=revenue_chart_data,
                           category_chart_labels=category_chart_labels,
                           category_chart_data=category_chart_data)


@app.route('/products')
def products():
    page = request.args.get('page', 1, type=int)
    category = request.args.get('category', '')
    sort = request.args.get('sort', 'default')

    # Start with base query
    query = Product.query

    # Apply category filter if specified
    if category:
        query = query.filter(Product.category == category)

    # Apply sorting based on selection
    if sort == 'price_asc':
        query = query.order_by(Product.price.asc())
    elif sort == 'price_desc':
        query = query.order_by(Product.price.desc())
    elif sort == 'name_asc':
        query = query.order_by(Product.name.asc())
    elif sort == 'name_desc':
        query = query.order_by(Product.name.desc())
    # Default sorting can be by ID or featured status or whatever makes sense for your site
    else:  # 'default' or any other value
        query = query.order_by(Product.id.desc())  # Newest products first

    # Paginate the results
    pagination = query.paginate(page=page, per_page=12, error_out=False)
    products = pagination.items

    return render_template('products.html', products=products, pagination=pagination)


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)


@app.route('/cart')
def cart():
    cart_items = flask_session.get('cart', {})
    products = []
    total = 0
    for product_id, quantity in cart_items.items():
        product = Product.query.get(int(product_id))
        total += product.price * quantity
        products.append({'product': product, 'quantity': quantity})
    return render_template('cart.html', products=products, total=total)


@app.route('/add_to_cart/<int:product_id>', methods=['GET', 'POST'])
@login_required
def add_to_cart(product_id):
    cart = flask_session.get('cart', {})

    # Get quantity from form data if it's a POST request, otherwise default to 1
    quantity = 1
    if request.method == 'POST':
        quantity = int(request.form.get('quantity', 1))

    # Add product to cart with specified quantity
    product_id_str = str(product_id)
    cart[product_id_str] = cart.get(product_id_str, 0) + quantity
    flask_session['cart'] = cart

    # Save cart action
    cart_item = CartItem(product_id=product_id, user_id=current_user.id, quantity=quantity)
    db.session.add(cart_item)
    db.session.commit()

    flash(f'Added {quantity} item(s) to cart!', 'success')
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/admin/products')
@login_required
@admin_required
def admin_products():
    products = Product.query.all()
    return render_template('admin_products.html', products=products)

@app.route('/admin/order/<int:order_id>/update-status', methods=['POST'])
@login_required
@admin_required
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')

    if new_status in ['processing', 'shipped', 'delivered', 'cancelled']:
        order.status = new_status
        db.session.commit()
        flash(f'Order #{order_id} status updated to {new_status.title()}', 'success')
    else:
        flash('Invalid status provided', 'danger')

    return redirect(url_for('admin_orders'))

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_users():
    # Handle POST requests (user edits and deletions)
    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')

        try:
            user_id = int(user_id)
            target_user = User.query.get_or_404(user_id)

            # Edit user
            if action == 'edit_user':
                username = request.form.get('username')
                email = request.form.get('email')
                name = request.form.get('name')
                is_admin = 'is_admin' in request.form
                new_password = request.form.get('new_password')

                # Validate username uniqueness (if changed)
                if username != target_user.username and User.query.filter_by(username=username).first():
                    flash('Username already exists!', 'danger')
                    return redirect(url_for('admin_users'))

                # Validate email uniqueness (if changed)
                if email != target_user.email and User.query.filter_by(email=email).first():
                    flash('Email already registered!', 'danger')
                    return redirect(url_for('admin_users'))

                # Update user information
                target_user.username = username
                target_user.email = email
                target_user.name = name
                target_user.is_admin = is_admin

                # Update password if provided
                if new_password and new_password.strip():
                    hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
                    target_user.password_hash = hashed_pw

                db.session.commit()
                flash(f'User {username} has been updated successfully!', 'success')

            # Delete user
            elif action == 'delete_user':
                # Prevent admins from deleting themselves
                if target_user.id == current_user.id:
                    flash('You cannot delete your own account!', 'danger')
                    return redirect(url_for('admin_users'))

                # Get username before deletion for the flash message
                username = target_user.username

                try:
                    # With cascade configured properly, this should delete related records
                    db.session.delete(target_user)
                    db.session.commit()
                    flash(f'User {username} has been deleted successfully!', 'success')
                except Exception as e:
                    db.session.rollback()
                    # More detailed error message for debugging
                    flash(f'Error deleting user: {str(e)}', 'danger')
                    print(f"Error deleting user {username}: {str(e)}")

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')

        return redirect(url_for('admin_users'))

    # GET request - display users
    users = User.query.all()
    return render_template('admin_users.html', users=users)


from wtforms import TextAreaField, SelectField


# Updated Order model with address fields
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    stripe_session_id = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='processing')
    date = db.Column(db.DateTime, default=datetime.utcnow)

    # Address fields
    shipping_address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    postal_code = db.Column(db.String(20), nullable=False)
    country = db.Column(db.String(100), nullable=False, default='United States')
    phone = db.Column(db.String(20), nullable=True)

    # Optional billing address (if different from shipping)
    billing_address = db.Column(db.Text, nullable=True)
    billing_city = db.Column(db.String(100), nullable=True)
    billing_state = db.Column(db.String(100), nullable=True)
    billing_postal_code = db.Column(db.String(20), nullable=True)
    billing_country = db.Column(db.String(100), nullable=True)

    @property
    def customer_name(self):
        user = User.query.get(self.user_id)
        return user.name if user else "Unknown"

    @property
    def customer_email(self):
        user = User.query.get(self.user_id)
        return user.email if user else "Unknown"


# New form for checkout with address collection
class CheckoutForm(FlaskForm):
    # Shipping Address
    shipping_address = TextAreaField('Shipping Address', validators=[DataRequired()],
                                     render_kw={"placeholder": "Street address, apartment, suite, etc."})
    city = StringField('City', validators=[DataRequired()])
    state = StringField('State/Province', validators=[DataRequired()])
    postal_code = StringField('Postal Code', validators=[DataRequired()])
    country = SelectField('Country', choices=[('United States', 'United States'),
                                              ('Canada', 'Canada'),
                                              ('United Kingdom', 'United Kingdom')],
                          default='United States')
    phone = StringField('Phone Number', validators=[])

    # Billing address option
    billing_same = BooleanField('Billing address is the same as shipping address', default=True)
    billing_address = TextAreaField('Billing Address', validators=[])
    billing_city = StringField('Billing City', validators=[])
    billing_state = StringField('Billing State/Province', validators=[])
    billing_postal_code = StringField('Billing Postal Code', validators=[])
    billing_country = SelectField('Billing Country', choices=[('United States', 'United States'),
                                                              ('Canada', 'Canada'),
                                                              ('United Kingdom', 'United Kingdom')],
                                  default='United States')

    submit = SubmitField('Place Order')


# Updated checkout route
@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart = flask_session.get('cart', {})
    if not cart:
        flash('Your cart is empty.', 'warning')
        return redirect(url_for('home'))

    form = CheckoutForm()

    # Calculate cart total and prepare line items
    line_items = []
    total = 0
    cart_products = []

    for product_id, quantity in cart.items():
        product = Product.query.get(int(product_id))
        if product:
            line_items.append({
                'price_data': {
                    'currency': 'usd',
                    'product_data': {'name': product.name},
                    'unit_amount': int(product.price * 100),
                },
                'quantity': quantity,
            })
            total += product.price * quantity
            cart_products.append({'product': product, 'quantity': quantity})

    if form.validate_on_submit():
        # Create Stripe checkout session
        stripe_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=line_items,
            mode='payment',
            success_url=url_for('checkout_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('cart', _external=True),
        )

        # Create order with address information
        order = Order(
            user_id=current_user.id,
            total_price=total,
            stripe_session_id=stripe_session['id'],
            shipping_address=form.shipping_address.data,
            city=form.city.data,
            state=form.state.data,
            postal_code=form.postal_code.data,
            country=form.country.data,
            phone=form.phone.data
        )

        # Add billing address if different
        if not form.billing_same.data:
            order.billing_address = form.billing_address.data
            order.billing_city = form.billing_city.data
            order.billing_state = form.billing_state.data
            order.billing_postal_code = form.billing_postal_code.data
            order.billing_country = form.billing_country.data

        db.session.add(order)
        db.session.commit()

        return redirect(stripe_session.url, code=303)

    return render_template('checkout.html', form=form, cart_products=cart_products, total=total)


# Updated checkout success route
@app.route('/checkout_success')
@login_required
def checkout_success():
    session_id = request.args.get('session_id')
    if session_id:
        # Verify the payment with Stripe
        try:
            session = stripe.checkout.Session.retrieve(session_id)
            if session.payment_status == 'paid':
                # Update order status
                order = Order.query.filter_by(stripe_session_id=session_id).first()
                if order:
                    order.status = 'confirmed'
                    db.session.commit()
        except Exception as e:
            print(f"Error verifying payment: {e}")

    flask_session.pop('cart', None)
    flash('Order placed successfully! You will receive a confirmation email shortly.', 'success')
    return redirect(url_for('home'))


# Updated admin orders route with better user data access
@app.route('/admin/orders')
@login_required
@admin_required
def admin_orders():
    # Join orders with users to get email addresses efficiently
    orders = db.session.query(Order, User).join(User, Order.user_id == User.id) \
        .order_by(Order.date.desc()).all()

    from flask_wtf import FlaskForm

    orders_with_users = []
    for order, user in orders:
        order.user = user
        orders_with_users.append(order)

    form = FlaskForm()
    return render_template('admin_orders.html', orders=orders_with_users , form = form)
@app.route('/admin/order/<int:order_id>')
@login_required
@admin_required
def admin_order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    return render_template('admin_order_detail.html', order=order)


@app.route('/admin/product/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        filename = save_product_image(form.image.data)
        product = Product(
            name=form.name.data,
            price=form.price.data,
            category=form.category.data,
            description=form.description.data,
            dimensions=form.dimensions.data,
            stock=form.stock.data,
            image_url=filename
        )
        db.session.add(product)
        db.session.commit()
        flash('Product added!', 'success')
        return redirect(url_for('admin_products'))
    return render_template('new_product.html', form=form)


@app.route('/admin/process-orders')
@login_required
@admin_required
def admin_process_orders():
    # This would be a page to process pending orders
    pending_orders = Order.query.filter_by(status='processing').all()
    return render_template('admin_process_orders.html', orders=pending_orders)


@app.route('/admin/inventory')
@login_required
@admin_required
def admin_inventory():
    # Inventory management page
    products = Product.query.order_by(Product.stock.asc()).all()
    return render_template('admin_inventory.html', products=products)

@app.route('/admin/reports')
@login_required
@admin_required
def admin_reports():
    orders = Order.query.all()
    total_revenue = 0.0
    for order in orders:
        try:
            total_revenue += float(order.total_amount)
        except (TypeError, ValueError):
            continue  # Or handle/log error
    total_revenue = round(total_revenue, 2)

    revenue_chart_labels = []
    revenue_chart_values = []

    return render_template('admin_reports.html', total_revenue=total_revenue, revenue_chart_labels=revenue_chart_labels,
        revenue_chart_values=revenue_chart_values)


@app.route('/admin/product/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    form = ProductForm(obj=product)
    if form.validate_on_submit():
        filename = save_product_image(form.image.data) if form.image.data else product.image_url
        product.name = form.name.data
        product.price = form.price.data
        product.category = form.category.data
        product.description = form.description.data
        product.stock = form.stock.data
        product.image_url = filename
        db.session.commit()
        flash('Product updated!', 'success')
        return redirect(url_for('admin_products'))
    return render_template('edit_product.html', form=form, product=product)


@app.route('/admin/product/delete/<int:product_id>', methods=['POST'])
@login_required
@admin_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted!', 'success')
    return redirect(url_for('admin_products'))


# Image paths fix routes
@app.route('/fix_upload_config')
@login_required
@admin_required
def fix_upload_config():
    """Update application configuration to save files to the correct path"""
    app.config['UPLOAD_FOLDER'] = CORRECT_UPLOAD_PATH
    flash('Upload folder configuration updated. Future uploads will be saved correctly.', 'success')
    return redirect(url_for('admin_products'))


@app.route('/move_existing_files')
@login_required
@admin_required
def move_existing_files():
    """Move existing product images to the correct directory"""
    moved_count = 0
    error_count = 0

    try:
        # Get all files from the current directory
        if os.path.exists(CURRENT_UPLOAD_PATH):
            files = os.listdir(CURRENT_UPLOAD_PATH)

            for filename in files:
                # Only move image files
                if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                    src_path = os.path.join(CURRENT_UPLOAD_PATH, filename)
                    dst_path = os.path.join(CORRECT_UPLOAD_PATH, filename)

                    try:
                        # Copy the file (use shutil.copy2 to preserve metadata)
                        shutil.copy2(src_path, dst_path)
                        moved_count += 1
                    except Exception as e:
                        error_count += 1
                        print(f"Error moving {filename}: {str(e)}")

            flash(f'Moved {moved_count} files. Errors: {error_count}', 'info')
        else:
            flash(f'Source directory {CURRENT_UPLOAD_PATH} does not exist!', 'danger')

    except Exception as e:
        flash(f'Error moving files: {str(e)}', 'danger')

    return redirect(url_for('admin_products'))


@app.route('/diagnose_image_paths')
@login_required
@admin_required
def diagnose_image_paths():
    """Display diagnostic information about image paths"""

    # Check if directories exist
    current_path_exists = os.path.exists(CURRENT_UPLOAD_PATH)
    correct_path_exists = os.path.exists(CORRECT_UPLOAD_PATH)

    # Get file listings
    current_files = os.listdir(CURRENT_UPLOAD_PATH) if current_path_exists else []
    correct_files = os.listdir(CORRECT_UPLOAD_PATH) if correct_path_exists else []

    # Get some sample products to check their image_url values
    sample_products = Product.query.limit(5).all()

    return render_template('diagnose_paths.html',
                           current_path=CURRENT_UPLOAD_PATH,
                           correct_path=CORRECT_UPLOAD_PATH,
                           current_path_exists=current_path_exists,
                           correct_path_exists=correct_path_exists,
                           current_files=current_files,
                           correct_files=correct_files,
                           sample_products=sample_products)


    # Save the template to the templates directory
    os.makedirs('templates', exist_ok=True)
    with open('templates/diagnose_paths.html', 'w') as f:
        f.write(template_content)

    flash('Diagnostic template created successfully!', 'success')
    return redirect(url_for('diagnose_image_paths'))


@app.route('/admin/fix_product_image_urls')
@login_required
@admin_required
def admin_fix_product_image_urls():
    """Admin route to fix product image URLs in the database"""
    updated_count = fix_product_image_urls()
    flash(f'Updated {updated_count} product image URLs in the database.', 'success')
    return redirect(url_for('admin_products'))



if __name__ == '__main__':
    # Create necessary directories if they don't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Create tables if they don't exist
    with app.app_context():
        db.create_all()

app.run(debug=True, host="0.0.0.0", port=3000)