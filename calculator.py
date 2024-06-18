from flask import Flask, render_template, request, redirect, url_for, flash, session , jsonify
from flask_login import current_user, login_required, login_user, logout_user, LoginManager, UserMixin
from flask_mysqldb import MySQL
from authlib.integrations.flask_client import OAuth
import os
from datetime import timedelta
from itsdangerous import URLSafeTimedSerializer as Serializer
from itsdangerous import URLSafeTimedSerializer
import paypalrestsdk
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from paypalrestsdk import Payment , exceptions
import stripe
from dotenv import load_dotenv
from flask_cors import CORS


load_dotenv()
app = Flask(__name__, static_url_path='/static')
CORS(app)
app.secret_key = 'xyzsdfg'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'social_media'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  
mysql = MySQL(app)

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# OAuth configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id="10478989205-tusa8f2mcetfuloba7eep5amrptus848.apps.googleusercontent.com",  
    client_secret="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",  
    access_token_url="https://oauth2.googleapis.com/token",
    access_token_params=None,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params=None,
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    client_kwargs={'scope': 'openid profile email'},
)
class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

    def get_id(self):
        return str(self.id)  

@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    if user:
        return User(id=user['id'], email=user['email'])  
    return None

@app.route('/')
def index():
    return render_template('calculator.html')

@app.route('/login')
def login():
    return render_template('account.html')

@app.route('/login/google')
def login_with_google():
    serializer = URLSafeTimedSerializer(app.secret_key)
    nonce = serializer.dumps({'csrf_token': 'abcdefg'}) 
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/login/callback')
def authorize():
    token = google.authorize_access_token()
    user_info = google.parse_id_token(token, nonce=session.get('nonce'))
    user_email = user_info['email']

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM users WHERE email = %s', (user_email,))
    user = cursor.fetchone()

    if user is None:
        cursor.execute('INSERT INTO users (email) VALUES (%s)', (user_email,))
        mysql.connection.commit()
        cursor.execute('SELECT * FROM users WHERE email = %s', (user_email,))
        user = cursor.fetchone()

    user_obj = User(id=user['id'], email=user['email'])
    login_user(user_obj)
    flash('Logged in successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('index'))


@app.route('/shopping_cart')
@login_required
def shopping_cart():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM cart_items WHERE user_id = %s', (current_user.id,))
    cart_items = cursor.fetchall()
    total = 0
    for item in cart_items:
        total += item['product_price']
    shipping_charges = float(total) * 0.10

    tax = float(total) * 0.08

    grand_total = float(total) + shipping_charges + tax

    return render_template('shopping_cart.html', cart_items=cart_items, total = session.get('total', 0), shipping_charges = session.get('shipping_charges', 0), tax=session.get('tax' , 0), grand_total=session.get('grand_total' ,0))
@app.route('/delete_from_cart/<int:product_id>')
@login_required
def delete_from_cart(product_id):
    cursor = mysql.connection.cursor()
    cursor.execute('DELETE FROM cart_items WHERE id = %s AND user_id = %s', (product_id, current_user.id))
    mysql.connection.commit()
    calculate_totals()
    flash('Product deleted from cart successfully!', 'success')
    return redirect(url_for('shopping_cart'))
@app.route('/men')
def men():
    return render_template('men.html')

@app.route('/women')
def women():
    return render_template('women.html')
def calculate_totals():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM cart_items WHERE user_id = %s', (current_user.id,))
    cart_items = cursor.fetchall()
    total = 0
    for item in cart_items:
     if item['product_price'] is not None and item['quantity'] is not None:
        total += item['product_price'] * item['quantity']
    shipping_charges = float(total) * 0.10
    tax = float(total) * 0.08
    grand_total = float(total) + shipping_charges + tax
    session['total'] = total
    session['shipping_charges'] = shipping_charges
    session['tax'] = tax
    session['grand_total'] = grand_total
    session.modified = True  
@app.route('/add_to_cart', methods=['GET', 'POST'])
def add_to_cart():
    if current_user.is_authenticated:
        product_name = request.form['product_name']
        product_price = request.form['product_price']
        product_price = float(product_price)
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM cart_items WHERE user_id = %s AND product_name = %s', (current_user.id, product_name))
        cart_item = cursor.fetchone()
        if cart_item:
            cursor.execute('UPDATE cart_items SET quantity = quantity + 1 WHERE user_id = %s AND product_name = %s', (current_user.id, product_name))
            mysql.connection.commit()
        else:
            cursor.execute('INSERT INTO cart_items (user_id, product_name, product_price, quantity) VALUES (%s, %s, %s, %s)', (current_user.id, product_name, product_price, 1))
            mysql.connection.commit()
        calculate_totals()
        flash('Item added to cart successfully!', 'success')
        return redirect(url_for('shopping_cart'))
    else:
        flash('Please login to add items to cart.', 'danger')
        return redirect(url_for('login'))


@app.route('/increase_quantity/<int:product_id>')
@login_required
def increase_quantity(product_id):
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM cart_items WHERE id = %s AND user_id = %s', (product_id, current_user.id))
    cart_item = cursor.fetchone()
    if cart_item:
        cursor.execute('UPDATE cart_items SET quantity = quantity + 1 WHERE id = %s AND user_id = %s', (product_id, current_user.id))
        mysql.connection.commit()
        calculate_totals()
        flash('Quantity increased successfully!', 'success')
    return redirect(url_for('shopping_cart'))

@app.route('/decrease_quantity/<int:product_id>')
@login_required
def decrease_quantity(product_id):
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM cart_items WHERE id = %s AND user_id = %s', (product_id, current_user.id))
    cart_item = cursor.fetchone()
    if cart_item:
        if cart_item['quantity'] > 1:
            cursor.execute('UPDATE cart_items SET quantity = quantity - 1 WHERE id = %s AND user_id = %s', (product_id, current_user.id))
            mysql.connection.commit()
            calculate_totals()
            flash('Quantity decreased successfully!', 'success')
        else:
            flash('Quantity cannot be less than 1!', 'danger')
    return redirect(url_for('shopping_cart'))


@app.route('/process_payment')
def process_payment():
   return render_template('payment.html')

stripe.api_key = 'sk_test_51POV5pLkVrTHamybbDAtKugqOURr8m8YO8helQXttYvHMUw5zwIkZ2uWemYCtj1lT8Pqsnnk47DIX2rgWGNffYVo00Wqa9K09c'

@app.route('/pay', methods=['POST'])
def pay():
    amount = request.form['amount']
    card_number = request.form['card_number']
    exp_month = request.form['exp_month']
    exp_year = request.form['exp_year']
    cvc = request.form['cvc']

    try:
        charge = stripe.Charge.create(
            amount=amount,
            currency='usd',
            description='Payment from user',
            source={
                'object': 'card',
                'number': card_number,
                'exp_month': exp_month,
                'exp_year': exp_year,
                'cvc': cvc
            }
        )
        return redirect(url_for('payment_success'))
    except stripe.error.CardError as e:
        return redirect(url_for('payment_error', error=e.user_message))

@app.route('/payment_success')
def payment_success():
    return 'Payment successful!'

@app.route('/payment_error')
def payment_error():
    error = request.args.get('error')
    return 'Payment failed: {}'.format(error)

if __name__ == '__main__':
    app.run(port=5000, debug=True)