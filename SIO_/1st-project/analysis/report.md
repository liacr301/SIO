# First SIO Project: DETI Store

## Index

1. [Introduction](#1-introduction)
2. [Overview](#2-overview)
3. [CWE Overview](#3-cwe-overview-table)
4. [Vulnerabilities](#4-vulnerabilities)
    1. [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](#41-cwe-79-improper-neutralization-of-input-during-web-page-generation-cross-site-scripting)
    2. [CWE 89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](#42-cwe-89-improper-neutralization-of-special-elements-used-in-an-sql-command-sql-injection)
    3. [CWE-20: Improper Input Validation](#43-cwe-20-improper-input-validation)
    4. [CWE-256: Plaintex Storage of a Password](#44-cwe-256-plaintex-storage-of-a-password)
    5. [CWE-521: Weak Password Requirements](#45-cwe-521-weak-password-requirements)
    6. [CWE-434: Unrestricted Upload of File with Dangerous Type](#46-cwe-434-unrestricted-upload-of-file-with-dangerous-type)
5. [Final considerations](#5-final-considerations)
6. [References](#6-references)


## 1. Introduction 
This report works as documention for the first SIO assignment, where it was requested that we devolep an insecure application of an e-commerce store and through the inspection of its vulnerabilities, we should create a secure version of the same application.
#
## 2. Overview
In this assignment we decided to work with Flask, using a SQLAlchemy database for persistence of the data and Jinja2 for rendering data in the templates. For the fronted we utilized pure HTML and CSS.
#
## 3. CWE Overview (Table)
| CWE    | Description | CVSS | String Vector | Fix |
| -------- | ------- | ------- | -------- | ------- |
| CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.   | 7.1 (High) | CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L     | Retrieve user input using methods provided by the request object, followed by thorough data validation and analysis. Ensure proper user input sanitization and escaping.
| CWE 89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data. | 9.8 (Critical) | CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H     | Use an ORM Object-Relational Mapping (like SQLAlchemy)
| CWE-20: Improper Input Validation    | The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly. | 5.5 (Medium) |CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H| Validate every input, has in making sure that every parameter follows the expected pattern and doesn't contain malicious sequences of characters. 
| CWE-256: Plaintex Storage of a Password   | Storing a plaintext password in a configuration file allows anyone who can read the file access to the password-protected resource.    | 9.6 (Critical)  |CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H  | Encode the passwords (for example, using an hash function) before storing them in the database.
| CWE-521: Weak Password Requirements   | The product does not require that users should have strong passwords, which makes it easier for attackers to compromise user accounts. | 7.5 (High) | CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | Alert the user about how strong their password is when creating an account and force them to follow a set of rules (for example, a password should at least be 8 characters long).
| CWE-434: Unrestricted Upload of File with Dangerous Type | The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment. | 7.5 (High) |CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | Use an "accept" atribute in the <input type="file"> element that only allows users to upload files of a certain type.
#

#### How did we calculate CVSS and the String Vector?


The Common Vulnerability Scoring System (CVSS) provides a way to capture the principal characteristics of a vulnerability and produce a numerical score reflecting its severity. The numerical score can then be translated into a textual representation, which is known as the Vector String. This Vector String reflects the values for each metric represented in the CVSS score.

To calculate the CVSS Vector String, we assess and score the following metrics that describe the characteristics of the vulnerability:

`Attack Vector (AV)` : This metric reflects how the vulnerability is exploited. E.g., local access (L), adjacent network (A), network (N).

`Attack Complexity (AC)`: This represents the complexity of the attack required to exploit the vulnerability. It can be low (L) or high (H).

`Privileges Required (PR)`: This indicates the level of privileges an attacker must possess for successful exploitation. It can be none (N), low (L), or high (H).

`User Interaction (UI)`: This metric determines if the vulnerability requires user participation to be exploited. It can be none (N) or required (R).

`Scope (S)`: This represents whether a vulnerability can affect resources beyond its security scope. It can be unchanged (U) or changed (C).

`Confidentiality (C), Integrity (I), and Availability (A)`: These metrics measure the impact on confidentiality, integrity, and availability of a system, respectively. They can be none (N), low (L), or high (H).


We used the [CVSS Calculator](https://www.first.org/cvss/calculator/3.0) to calculate the CVSS and the String Vector.



## 4. Vulnerabilities
### 4.1. CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### 4.2. CWE 89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### 4.3. CWE-20: Improper Input Validation


### 4.4. CWE-256: Plaintex Storage of a Password
* CVSS: 9.6 (Critical)
* String Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H

If the password is stored in plain text in the database that means that if an attacker gains access to that same database, they will be able to see the password in plain text, in other words, the real value of the password that allows them to enter the victims account.

This is a critical vulnerability, as it allows the attacker to gain access to the user's account, and potentially to other accounts if the user uses the same password in multiple websites.


#### Here is an example of the vulnerability:


This table shows how the User informations are being saved:

| ID | Username    | Password Hash   | Gender | Name           | Email                  | Status |
|----|-------------|-----------------|--------|----------------|------------------------|--------|
| 1  | joaozinho   | `Joaozinho%123` | Male   | joao           | joaozinho@gmail.com    | 0      |
| 2  | test        | `&Testes123`    | Male   | Test           | test@ua.pt             | 0      |


The attacker in the login page uses the improper input validation vulnerability to inject a SQL command (SELECT username, password FROM User) that will always return all the users and their passwords.

#### Here is an example of the fix:
```python
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if  form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, gender=form.gender.data, full_name=form.full_name.data, email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
       user = User.query.filter_by(username = form.username.data).first()
       if user and bcrypt.check_password_hash(user.password, form.password.data):
           login_user(user, remember = form.remember.data)
           return redirect(url_for('catalog'))
       else:
           session.pop('_flashes', None)  # clear all flash messages
           flash('Invalid username or password')
           
    return render_template('login.html', form = form)
```
We added the following line to the regiter function:
```
hashed_password = bcrypt.generate_password_hash(form.password.data)
```
And the following condition to the login function:
```
if bcrypt.check_password_hash(user.password, form.password.data):
```


For fixing this vulnerability, we used the library flask_bcrypt, which allows us to hash the password before storing it in the database. 

This way, even if the attacker gains access to the database (using the same command as above), they will not be able to see the password in plain text, as it will be in a not-human readable format.

The attacker still has access to the hashed password, but it will be much more difficult to crack it.

Now the table of how the User informations are being saved, is this:

| ID | Username    | Password Hash                                                      | Gender | Name           | Email                  | Status |
|----|-------------|--------------------------------------------------------------------|--------|----------------|------------------------|--------|
| 1  | joaozinho   | `$2b$12$8gqYrNip2TMhS/yFRzLHduIe6Jae.Q/owMKh8LgkqQMDrgPJXSvza`     | Male   | joao           | joaozinho@gmail.com    | 0      |
| 2  | test        | `$2b$12$nhQeraU.q/aNafddjn.09Obm9pp8Q1CcG2yg1D15jX4HMzfg5.WZS`     | Male   | Test           | test@ua.pt             | 0      |


### 4.5. CWE-521: Weak Password Requirements
* CVSS: 7.5 (High)
* String Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

When the password requirements are weak, it makes it easier for the attacker to guess the password, which can lead to the attacker gaining access to the user's account.

A weak password is short, common, a system default, or something that could be rapidly guessed by executing a brute force attack using a subset of all possible passwords, such as words in the dictionary, proper names, words based on the user name or common variations on these themes.

The attacker can easily steal user password using generic attack techniques (e.g. brute force attacks, authentication challenge theft, etc.)

### Here is an example of the vulnerability:

The user is creating an account, and the password requirements are weak, which means that the user can use a weak password, like "12345678".

* image *

### Here is an example of the fix:


On the register form, we added the following code to verify if the password is strong enough:

```python
    def validate_password(self, password):
        passw = password.data
        special_chars = "~!@#$%^&*()_+{}:;[]"
            
        if len(passw) < 8:
            raise ValidationError('Password must be at least 8 characters long.')
            
        if not any(char.isdigit() for char in passw):
            raise ValidationError('Password must contain at least one digit.')
            
        if not any(char.isupper() for char in passw):
            raise ValidationError('Password must contain at least one uppercase letter.')
            
        if not any(char.islower() for char in passw):
            raise ValidationError('Password must contain at least one lowercase letter.')
            
        if not re.search(r"[~\!@#\$%\^&\*\(\)_\+{}:;'\[\]]", passw):
            raise ValidationError(f'Password must contain at least one special character. {special_chars}')
            
        if re.search(r"[^a-zA-Z0-9~\!@#\$%\^&\*\(\)_\+{}\":;'\[\]]", passw):
            raise ValidationError(f'Password contains invalid character.\nOnly alphanumeric characters and these special characters are allowed: {special_chars}')
            
        return True
```

Now the user will be notify if the password is not strong enough, and will be forced to create a stronger password.

* image *

### 4.6. CWE-434: Unrestricted Upload of File with Dangerous Type

* CVSS: 7.5 (Hgh)
* String Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

If an application allows it's users to upload files of unristricted types, an attacker might use this lack of security to upload a risky type of file, that can be manipulated within the website and, therefore, putting it's users in danger.



### Here is an example of the vulnerability:

An attacker uploads a file in the products' review section. It was suposed for users to upload pictures of the product they order alongside their review in this field, however the bad actor sends a .exe file.
In the insecure website this happens since the line where the upload is made hasn't got any analysis/validation about the file that is being posted, as you can observe next:

```html
<input type="file" name="file" id="file">
```

* image *

### Here is an example of the fix:

To fix this vulnerability, we implemented an "accept" atributte containing only image types in the same line of html code.

```html
<input type="file" name="file" id="file" accept=".jpg, .png, .gif">
```

Now, when a user tries to choose a file from their desktop environment, they will only be able to search for .jpg, .png and .gif types. Other types of files don't even show up in the search window.

* image *

## 5. Final considerations
In this report we performed a thorough analysis of the CWEs (Common Weakness Enumeration) that we could find in our website.

We have looked into each of the six discovered vulnerabilities, examining the issues that could arise due their existence and detailing ways to resolve them.

This project provided us with a great understanding of the necessity of creating secure websites as not to suffer attacks which may have catastrophic consequences.

#
## 6. References
1. Slides provided in the curricular unit's e-learning page.

2. [CWE Mitre](https://cwe.mitre.org/)

3. [Flask Documentation](https://flask.palletsprojects.com/en/3.0.x/)

4. [Jinja Documentation](https://jinja.palletsprojects.com/en/3.1.x/)

5. [WTForms Documentation](https://wtforms.readthedocs.io/en/3.1.x/)

6. [SQLAlchemy Documentation](https://docs.sqlalchemy.org/en/14/)

7. [Flask-Bcrypt Documentation](https://flask-bcrypt.readthedocs.io/en/latest/)

8. [CVSS Calculator](https://www.first.org/cvss/calculator/3.0)
