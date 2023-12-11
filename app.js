const express = require('express')
const ejs = require('ejs')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const PORT = process.env.PORT || 3000

const app = express()

app.use(express.static('public'))
app.set('view engine','ejs')
app.use(bodyParser.urlencoded({ extended: true}))

app.get('/',(req,res)=>{
    res.render('home')
})









app.listen(PORT,()=>{
    console.log(`Server Running on Port ${PORT}`)
})