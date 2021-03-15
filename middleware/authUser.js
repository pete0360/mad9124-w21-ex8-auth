import jwt from 'jsonwebtoken'
const jwtSecretKey = 'supersecretkey'

function parseToken(headerValue) {
    if (headerValue) {
    const [type, token] = headerValue.split(' ')
    if (type === 'Bearer' && typeof token !== 'undefined') {
        return token
    }
    return undefined
    }
}



export default function (req, res, next) {
     // Get the JWT from the request header
    const headerValue = req.header('Authorization')
    const token = parseToken(headerValue)
    if(!token){
        return res.status(401).send({
            errors: [
                {
                    status: '401', 
                    title: 'Authentication failed reeeeeeeeeeee',
                    description: 'Missing bearer token'
                }
            ]
        })
    }
    // Validate the JWT
    
    try{
    const payload = jwt.verify(token, jwtSecretKey, {algorithm: 'HS256'})
    req.user = { _id: payload.uid}
    next()
    } catch(err){
        res.status(401).send({
            errors: [
                {
                    status: '401', 
                    title: 'Authentication failed reeeeeeeeeeee',
                    description: 'Missing bearer token'
                }
            ]
        })
    }






    // TODO: Load the User document from the database using the `_id` in the JWT
}



/// client code 
// const token = 'weiufhwifughwefwFHEdsdjfasdkf'
// fetch('/auth/users/me', {
//     method: 'GET',
//     headers: {
//         Authentication: `Bearer ${token}`
//     }
// })