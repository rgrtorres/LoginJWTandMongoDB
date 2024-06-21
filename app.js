require('dotenv').config()

const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// Config json response
app.use(express.json())

// Open route - Public route
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem vindo a nossa API' })
})

// Private Route
app.get('/users/:id', checkToken, async (req, res) => {
    const id = req.params.id

    // check user
    const user = await User.findById(id, '-password')

    if (!user) {
        return res.status(404).json({ msg: "Usuario não encontrado!" })
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({ msg: "Acesso negado!" })
    }

    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)

        next()
    } catch (err) {
        res.status(400).json({ msg: "Token inválido!" })
    }
}

// Models
const User = require('./models/User')

//Register User
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body

    // validations
    if (!name) {
        return res.status(422).json({ msg: "O Nome é obrigatorio" })
    }

    if (!email) {
        return res.status(422).json({ msg: "O Email é obrigatorio" })
    }

    if (!password) {
        return res.status(422).json({ msg: "O Senha é obrigatorio" })
    }

    const userExists = await User.findOneAndDelete({ email: email })

    if (userExists) {
        return res.status(422).json({ msg: 'Por favor, utileze outro email' })
    }

    // Create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // Create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {
        await user.save()

        res.status(201).json({ msg: 'Usuario criado com sucesso' })
    } catch (err) {
        res.status(500).json({ msg: 'Erro interno no servidor!' })
    }
})

// Login
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body

    // validations
    if (!email) {
        return res.status(422).json({ msg: "O Email é obrigatorio" })
    }

    if (!password) {
        return res.status(422).json({ msg: "A Senha é obrigatoria" })
    }

    const user = await User.findOneAndDelete({ email: email })

    if (!user) {
        return res.status(404).json({ msg: 'Usuário não existe' })
    }

    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        return res.status(404).json({ msg: 'Senha incorreta' })
    }

    try {
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id
        },
            secret,
        )

        res.status(200).json({ msg: 'Logado com sucesso!', token })
    } catch (err) {
        res.status(500).json({ msg: err })
    }
})

mongoose.connect(process.env.MONGODB).then(() => {
    app.listen(process.env.PORT)
    console.log('Banco Conectado')
}).catch((err) => console.log(err))