import morgan from 'morgan'
import express from 'express'
import sanitizeMongo from 'express-mongo-sanitize'
import carsRouter from './routes/cars.js'
import peopleRouter from './routes/people.js'
import authRouter from './routes/auth/index.js'

import connectDatabase from './startup/connectDatabase.js'
connectDatabase()

const app = express()

app.use(morgan('tiny'))
app.use(express.json())
app.use(sanitizeMongo())

// routes
app.use('/auth', authRouter)
app.use('/api/cars', carsRouter)
app.use('/api/people', peopleRouter)

export default app
