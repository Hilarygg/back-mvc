const bcrypt = require('bcrypt')
const jsonwebtoken = require('jsonwebtoken')
const { createUser, findUserByEmail } = require('../services/userService')
const { json } = require('express')

exports.signup = async (req, res) =>{
    try {
        //Código para registrarse
        const { email, password } = req.body 
        const existingUser = await findUserByEmail(email)
        if (existingUser.success){
            return res.status(400).json({
                message: 'El usuario ya está registrado'
            })
        }

        const saltRounds = 10 
        const hashedPassword = await bcrypt.hash(password, saltRounds)

        const newUser = {
            email: email,
            password: hashedPassword
            //agregar otros campos
        }
        const userResult = await createUser(newUser)
        if (userResult.success) {
            res.status(201).json({
                message: 'Usuario Registrado Satisfactoriamnete'
            })
        } else {
            res.status(500).json({
                message: 'Error al registrar el Usuario'
            })
        }
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.login = async (req, res) =>{
    try {
        //Código para loggearnos
            const { email, password } = req.body
            const findEmail = await findUserByEmail(email)

            if(!findEmail.success) {
                res.status(401).json({
                    message: 'Usuario no encontrado'
                })
            
            }

            const user = findEmail.user
            const findPassword = await bcrypt.compare(password, user.password)
            if(!findPassword.success) {
                res.status(401).json({
                 message: 'Password Incorrecta'
                })
            }      

            const token = jsonwebtoken.sign({
            email: user.email,
            userId: user.id
            }, process.env.TOPSECRET, {
            expiresIn: '1h'
            })

            res.status(200).json({
            token: token
            })
    } catch (error) {
            res.status(500).json({
            message: error.message
            })
    }
}