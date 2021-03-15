import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import bcrypt from 'bcrypt'

const jwtSecretKey = 'supersecretkey'
const saltRounds = 14

export const schema = new mongoose.Schema({
    firstName: {type: String, trim: true, required: true},
    lastName: {type: String, trim: true, required: true},
    email: {type: String, trim: true, required: true},
    password:{type: String, trim: true, required: true}
})

schema.methods.generateAuthToken = function () {
    const payload = {uid: this._id }
    return jwt.sign(payload, jwtSecretKey, {expiresIn: '1h', algorithm: 'HS256' }) 
}

schema.methods.toJSON = function () {
    const obj = this.toObject() //
    delete obj.password
    delete obj.__v
    return obj
}


schema.statics.authenticate = async function (email, password) {
    const user = await this.findOne({ email: email })
    const hashedPassword = user
    ? user.password
    : `$2b$${saltRounds}$invalidusernameaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
    const passwordDidMatch = await bcrypt.compare(password, hashedPassword)

    return passwordDidMatch ? user : null
    // remember if the email did not match, user === null
}

schema.pre('save', async function (next) {
    if(!this.isModified('password')) return next()

    this.password = await bcrypt.hash(this.password, saltRounds)
    next()
})


const Model = mongoose.model('User', schema)

export default Model