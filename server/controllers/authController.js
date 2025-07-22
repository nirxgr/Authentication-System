import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import resend from '../config/resend.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from "../config/emailTemplates.js";
import transporter from "../config/resend.js";

export const register = async (req,res) => {
    const {name,email,password} = req.body;

    if(!name || !email || !password){
        return res.json({success: false, message: "Missing Details"})
    }

    try {
        const existing = await userModel.findOne({email});
        if(existing){
            return res.json({success: false, message: "User already exists"});
        }
        //10 is the level of complexity of encrypted password
        const hashedPassword = await bcrypt.hash(password,10);
        const user = new userModel({name, email, password: hashedPassword });
        await user.save();
        
        //token
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: "7d"});
        //cookie functionality
        res.cookie('token', token,{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? "none" : 'strict',
            maxAge: 7 * 24 * 60 * 1000
        })
        //Sending welcome email
        const info = await transporter.sendMail({
        from: `"Authentication System" <${process.env.GMAIL_USER}>`,
        to: email,
        subject: 'Welcome to Authentication System!',
        html: `<h2>Welcome, ${name}!</h2>
                <p>Your account has been successfully created using this email: <strong>${email}</strong>.</p>
                <p>We're glad to have you on board!</p>`
        });

        console.log('Email sent:', info.messageId);

        return res.json({success: true, message: "User registered successfully"});

    } catch(error){
        res.json({success: false, message: error.message})
    } 
}


export const login = async (req, res) => {
    
    const { email, password } = req.body;
    // trim to avoid spaces-only inputs
    if(!email?.trim() || !password?.trim()){
        return res.json({success: false, message: "Email and password are required."})
    }

    try {
        const user = await userModel.findOne({email});
        if(!user) return res.status(401).send("User not found");

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({success: false,message: "Invalid credentials"});
        }

        //token
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: "7d"});
        //cookie functionality
        res.cookie('token', token,{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? "none" : 'strict',
            maxAge: 7 * 24 * 60 * 1000
        })
        return res.json({success: true, message: "Login successful"})
        

    } catch(error){
        res.json({success: false, message: error.message})
    } 
}


export const logout = async (req,res) => {

    try{
        res.clearCookie('token',{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? "none" : 'strict',
        })
        return res.json({success: true, message: "Logged Out"}) 

    } catch(error){
        res.json({success: false, message: error.message})
    }
}


export const sendVerifyOtp = async (req,res) => {
    try{
        const userId = req.user.id;

        const user = await userModel.findById(userId);

        if(user.isAccountVerified){
            return res.json({success: false, message: "Account already verified"})
        }
        const otp = String(Math.floor(100000 + Math.random()* 900000));
        user.verifyOtp = otp;
        user.verifyOtpExpiresAt = Date.now() + 30 * 60 * 1000;

        await user.save();

        //Sending otp
        const info = await transporter.sendMail({
        from: `"Authentication System" <${process.env.GMAIL_USER}>`,
        to: user.email,
        subject: 'Account Verification OTP',
        html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
        });
        

        console.log('Email sent:', info.messageId);

        res.json({success: true, message: 'Verification OTP Sent on Email'});

    } catch(error){
        res.json({success: false, message: error.message})
    }
}


export const verifyEmail = async (req,res) => {
    const {otp} = req.body;
    const userId = req.user.id;

    if(!userId || !otp) {
        return res.json({success: false, message: "Missing Details"})
    }
    try {
        const user = await userModel.findById(userId);

        if(!user) {
            return res.json({success: false, message: "User Not Found"});
        }
        if(user.verifyOtp === '' || user.verifyOtp !== otp){
            return res.json({success: false, message: "Invalid OTP"});
        }
        if (Date.now() > user.verifyOtpExpiresAt) {
             return res.json({success: false, message: "OTP Expired"});
        }  
        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpiresAt=0;
        
        await user.save();
        return res.json({success: true, message: 'Email Verified successfully.'});


    } catch(error){
        res.json({success: false, message: error.message})
    }
}


//check if user is authenticated
export const isAuthenticated = async (req,res) => {
    
    try{
        return res.json({success: true});
    } catch (error) {
        res.json({ success: false, message: error.message});
    }

}

//send password reset otp
export const sendPasswordResetOtp = async (req,res) => {

    const {email} = req.body;

    if(!email){
        return res.json({success: false, message: "Email is required"})
    }

    try {

        const user = await userModel.findOne({email});
        if(!user){
            return res.json({ success: false, message: "User not found"});
        }
         const otp = String(Math.floor(100000 + Math.random()* 900000));
        user.resetOtp = otp;
        user.resetOtpExpiresAt = Date.now() + 15 * 60 * 1000;

        await user.save();

        //Sending reset password email
        const info = await transporter.sendMail({
        from: `"Authentication System" <${process.env.GMAIL_USER}>`,
        to: user.email,
        subject: 'Password Reset OTP',
        html:PASSWORD_RESET_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
        })

        console.log('Email sent:', info.messageId);

        res.json({success: true, message: 'Password Reset OTP Sent on Email'});



    } catch (error){
        res.json({success: false, message: error.message})
    }
}

// Reset user password
export const resetPassword = async (req,res) => {
    const {email,otp,newPassword} = req.body;
    if(!email || !otp || !newPassword){
        return res.json({success: false, message: "Email, OTP and New Password are required"});
    }
    try {
        const user = await userModel.findOne({email});
        if (!user){
            return res.json({success: false, message: "User not found"});
        }

        if(user.resetOtp === "" || user.resetOtp !== otp){
            return res.json({success: false, message: "Invaid OTP"});
        }
        if(user.resetOtpExpiresAt < Date.now()){
            return res.json({success: false, message: "OTP Expired"});
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOtp = "";
        user.resetOtpExpiresAt = 0;

        await user.save();

        return res.json({success: true, message: "Password has been reset successfully."})


    } catch(error){
        return res.json({success: false, message: error.message});
    }

}