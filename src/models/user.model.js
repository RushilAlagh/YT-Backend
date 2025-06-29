import mongoose from "mongoose"
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        index: true, // Optimizes searching in a database
        lowercase: true,
        trim: true
    },
    _id: {
        type: String,
        required: true,
        unique: true,
    },
    email: {
        type: String,
        unique: true,
        lowercase: true,
        required: true,
        trim: true
    },
    fullName: {
        type: String,
        required: true,
        trim: true,
        index: true
    },
    avatar: {
        type: String, // cloudinery url
        required: true
    },
    coverImage: {
        type: String,
    },
    watchHistory: [
        {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Video",
        required: true
        }
    ],
    password: {
        type: String,
        required: [true, "Password is required"],
        unique: true
    },
    refreshToken: {
        type: String,
    }
}, {timestamps: true})

userSchema.pre("save", async function (next) { // pre is a hook in middleware that defines an action to be performed before some task, in our case hashing passwords before they are saved in database
    if(!this.isModified("password")) return next(); // what we did was that we were trying to encrypt the password everytime a user saves something but it can be upadting the avatar as well and in that case we dont want to encrypt the password again so we have implemented an if condition checking if the password has been modified
    this.password = bcrypt.hash(this.password, 10) 
    next()
})

userSchema.methods.isPasswordCorrect = async function (password){
    return await bcrypt.compare(password, this.password) // password is the password entered by user and this.password is the encrypted password and we get a boolean result
}

userSchema.methods.generateAccessToken = function(){
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username,
            fullName: this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}

userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

export const User = mongoose.model("User", userSchema);