#imports
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
CORS(app)

#DB Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:password@localhost/cve_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

#Tables to Models
class CVE(db.Model):
    __tablename__ = 'cves'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    severity = db.Column(db.String, nullable=False)
    mitigations = db.Column(db.String)

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String, nullable=False)

class ProductVulnerability(db.Model):
    __tablename__ = 'product_vulnerabilities'
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.Integer, db.ForeignKey('cves.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    vulnerable = db.Column(db.Boolean, default=True)
    state = db.Column(db.String)
    last_date_reviewed = db.Column(db.String)

#Homepage route
@app.route('/')
def index():
    return render_template('index.html')

#Route for search
@app.route('/search_cves', methods=['GET'])
def search_cves():
    
    #Query Parameters
    search_query = request.args.get('search', '')
    product_filter = request.args.get('product', 'all')
    state_filter = request.args.get('state', 'all')
    severity_filter = request.args.get('severity', 'all')

    #Base Query
    query = db.session.query(CVE, ProductVulnerability, Product).join(
        ProductVulnerability, CVE.id == ProductVulnerability.cve_id
    ).join(Product, Product.id == ProductVulnerability.product_id)

    #Filters
    if search_query:
        
        #Parses cve name and description
        query = query.filter(
            (CVE.name.ilike(f'%{search_query}%')) | (CVE.description.ilike(f'%{search_query}%'))
        )
    
    #Filter by name
    if product_filter != 'all':
        query = query.filter(Product.product_name == product_filter)
    
    #Filter by state
    if state_filter != 'all':
        query = query.filter(ProductVulnerability.state == state_filter)

    
    #Filter by severity
    if severity_filter != 'all':
        query = query.filter(CVE.severity == severity_filter)

    #Limits results to 100 to not run out of memory
    results = query.limit(100).all()

    #JSON response
    cve_list = []
    for cve, vulnerability, product in results:
        cve_data = {
            'name': cve.name,
            'description': cve.description,
            'dateReviewed': vulnerability.last_date_reviewed,
            'severity': cve.severity,
            'state': vulnerability.state,
            'productAffected': product.product_name,
            'solution': cve.mitigations,
        }
        cve_list.append(cve_data)

    return jsonify(cve_list)

#Prevents memory leaks by closing connections
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

if __name__ == '__main__':
    app.run(debug=True)