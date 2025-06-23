# 🏨 G-Hostel Website

A complete web-based hostel management system designed to streamline hostel activities like room allotment, student registration, warden controls, and fee tracking. This project is ideal for hostel administrators, wardens, and students to interact in a digital, efficient environment.

## 🚀 Features

- 🧑‍🎓 **Student Registration & Login**
- 🏢 **Room Booking & Allotment**
- 💳 **Fee Management System**
- 🔐 **Admin/Warden Panel**
- 📊 **Dashboard for Overview**
- ✉️ **Contact Page**
- 🔍 **Search & Filter Functionalities**

## 🛠️ Technologies Used

- **Frontend**: HTML5, CSS3, JavaScript
- **Backend**: PHP
- **Database**: MySQL
- **Tools**: XAMPP / WAMP for local development

## 📁 Project Structure

```
G-Hostel-Website/
├── admin/
├── student/
├── css/
├── js/
├── includes/
├── images/
├── database/
│   └── ghostel.sql
├── index.php
└── README.md
```

## 🖥️ Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/allakaushik/G-Hostel-Website.git
   ```

2. **Setup Local Server**
   - Use [XAMPP](https://www.apachefriends.org/index.html) or [WAMP](https://www.wampserver.com/) to run Apache & MySQL.

3. **Import Database**
   - Open `phpMyAdmin`.
   - Create a database named `ghostel`.
   - Import the `ghostel.sql` file from the `database/` folder.

4. **Run the Application**
   - Place the project folder inside `htdocs` (for XAMPP) or `www` (for WAMP).
   - Start Apache and MySQL servers.
   - Navigate to `http://localhost/G-Hostel-Website` in your browser.

## 👤 Admin Credentials

Use the following default credentials to log in as an admin:
- **Username**: `admin`
- **Password**: `admin123`  
*(You can change this from the database manually.)*

## 📸 Screenshots

| Login Page | Admin Dashboard | Student Panel |
|------------|-----------------|----------------|
| ![Login](images/screenshot-login.png) | ![Admin](images/screenshot-admin.png) | ![Student](images/screenshot-student.png) |

## ✅ To-Do / Improvements

- Implement password encryption (bcrypt or PHP password_hash)
- Improve UI/UX with modern design frameworks
- Add email verification
- Mobile responsiveness
- Role-based access control

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create your feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -m 'Add new feature'`
4. Push to the branch: `git push origin feature-name`
5. Open a pull request

