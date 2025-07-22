import mongoose from "mongoose";
// import {Schema,model} from "mongoose";(IF THIS IS USED WE HAVE TO WRITE DIRECTLY Schema and all) 


const userSchema = new mongoose.Schema({
    name: {type: String, required: true},
    email: {type: String, required: true, unique: true},
    password: {type: String, required: true},
    verifyOtp: {type: String, default:''},
    verifyOtpExpireAt: {type: Number, default: 0},
    isAccountVerified: {type: Boolean, default: false},
    resetOtp: {type: String, default: ''},
    resetOtpExpireAt: {type: Number, default: 0},
    
});


//IF USER MODEL EXISTS IT USES THIS OR CREATES NEW ONE
const userModel = mongoose.models.user || mongoose.model('user', userSchema);
export default userModel;
