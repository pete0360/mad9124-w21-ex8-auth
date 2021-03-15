// import jwt from 'jsonwebtoken'
// import bcrypt from 'bcrypt'
import createDebug from 'debug'
import express from 'express'
import sanitizedBody from '../../middleware/sanitizeBody.js'
import User from '../../models/User.js'
import authUser from '../../middleware/authUser.js'

const jwtSecretKey = 'supersecretkey' //dont do this in production application
const debug = createDebug('week8:authRouter')
const router = express.Router()

// const saltRounds = 14

router.post('/users',sanitizedBody, async (req, res,) => {
    try{
        const newUser = new User(req.sanitizedBody) 
        // newUser.password = await bcrypt.hash(newUser.password, saltRounds)
        const itExists = Boolean(
            await User.countDocuments({email: newUser.email})
        )
        if (itExists){ 
            return res.status(400).send({
                errors: [
                    {
                        status: '400',
                        title: 'Validation Error',
                        description: `email address ${newUser.email} is already registered`,
                        source: {pointer: '/data/attributes/email'}
                    }
                ]
            })
        }
        await newUser.save()
        res.status(201).send( {data: newUser })
    } catch (err){
        console.log(err)
        res.status(500).send({
            errors:[
                {
                    status: '500',
                    title: "Server Error",
                    description: 'Problem Saving document'
                }
            ]
        })
    }
})

router.get('/users/me', authUser, async (req, res) => {
    // const id = req.user._id
    const user = await User.findById(req.user._id) //.select('-password -__v') made irrelevant by redacting in User.js
    res.send({data: user})

    // Remember to redact sensitive data like the user's password
    // Send the data back to the client.

})

router.post('/tokens', sanitizedBody, async (req, res) => {
    const { email, password } = req.sanitizedBody
    const user = await User.authenticate(email, password)

    if (!user) {
        return res.status(401).send({ errors: ['we will build this later'] })
    }


/////////////////////////Old code///////////////////////////////////////////////////////////////////

//     const user = await User.findOne({ email: email })
//     if (!user) {
//         return res.status(401).send({ errors: ['we will build this later'] })
//     }

//     // check if the payload.username is valid
//     // retrieve the stored password hash
//     // compare the payload.password with the hashed password
//     // if all is good, return a token
//     // if any condition failed, return an error message


//     const hashedPassword = user ? user.password : `$2b$${saltRounds}$invalidusernameaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`

//     const passwordDidMatch = await bcrypt.compare(password, hashedPassword)

//     if (!passwordDidMatch) {
//     return res.status(401).send({ errors: ['we will build this later'] })
//     }
//   // if all is good, return a token
//   // if any condition failed, return an error message
//     // const payload = {uid: user._id }



    res.status(201).send({ data: { token: user.generateAuthToken() } })  


})


export default router