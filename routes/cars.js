import createDebug from 'debug'
import sanitizeBody from '../middleware/sanitizeBody.js'
// import Car from '../models/Car.js'
import {Car} from '../models/index.js'
import express from 'express'

const debug = createDebug('week8:routes:cars')
const router = express.Router()

router.get('/', async (req, res) => {
  const collection = await Car.find().populate('owner')
  res.send({ data: collection })
})

router.post('/', sanitizeBody, async (req, res) => {
  let newDocument = new Car(req.sanitizedBody)
  try {
    await newDocument.save()
    res.status(201).send({ data: newDocument })
  } catch (err) {
    debug(err)
    res.status(500).send({
      errors: [
        {
          status: '500',
          title: 'Server error',
          description: 'Problem saving document to the database.',
        },
      ],
    })
  }
})

router.get('/:id', async (req, res) => {
  try {
    const car = await Car.findById(req.params.id).populate('owner')
    if (!car) throw new Error('Resource not found')
    res.send({ data: car })
  } catch (err) {
    sendResourceNotFound(req, res)
  }
})

const update = (overwrite = false) => async (req, res) => {
  try {
    const course = await Car.findByIdAndUpdate(
      req.params.id,
      req.sanitizedBody,
      {
        new: true,
        overwrite,
        runValidators: true,
      }
    )
    if (!course) throw new Error('Resource not found')
    res.send({ data: course })
  } catch (err) {
    sendResourceNotFound(req, res)
  }
}
router.put('/:id', sanitizeBody, update(true))
router.patch('/:id', sanitizeBody, update(false))

router.delete('/:id', async (req, res) => {
  try {
    const car = await Car.findByIdAndRemove(req.params.id)
    if (!car) throw new Error('Resource not found')
    res.send({ data: car })
  } catch (err) {
    sendResourceNotFound(req, res)
  }
})

function sendResourceNotFound(req, res) {
  res.status(404).send({
    error: [
      {
        status: '404',
        title: 'Resource does nto exist',
        description: `We could not find a car with id: ${req.params.id}`,
      },
    ],
  })
}

export default router
