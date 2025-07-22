import nodemailer from 'nodemailer'
const transporter = nodemailer.createTransport({
    service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER, // your email
    pass: process.env.GMAIL_APP_PASSWORD, // app password from Google
  },

})

export default transporter;