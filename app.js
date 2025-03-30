const express=require('express')
const app=express()
const cookieParser = require("cookie-parser");
const bcrypt=require('bcrypt')
// using jwt for login it and giving the token till it is loggedin avoiding login at multiple steps
const jwt=require('jsonwebtoken')


const userModel=require('./models/user')
const postModel=require('./models/post')

app.set("view engine", "ejs")
app.use(express.json())
app.use(express.urlencoded({extension: true}))
app.use(cookieParser())

app.get('/', (req, res)=>{
    res.render("index")
})

app.post("/register", async(req, res)=>{
    let{username, name, age, email, password}=req.body

    let user=await userModel.findOne({email})
    if(user){
        return res.redirect('/login')
    }

    bcrypt.genSalt(10, (err, salt)=>{
        bcrypt.hash(password, salt, async (err, hash)=>{
            let newUser = await userModel.create({
                username,
                name,
                email,
                age,
                password:hash
            })
            await newUser.save()

            let token = jwt.sign({email:email, userid: newUser._id}, "shhh")
            res.cookie("token", token)
            res.send("Registered")

        })
    })

    // //Creating a new user without pw hashing
    // let newUser=new userModel({username, name, age, email, password})
    // await newUser.save()
    // res.status(201).send("user registered Successfully")

})

app.get('/login', (req, res)=>{
    res.render('login')
})

app.get('/profile',isLoggedIn, (req, res)=>{
    console.log(req.user)
    res.render("login")
})

app.post('/login', async (req, res)=>{
    let{email, password}=req.body;
    let user= await userModel.findOne({email})
    if(!user){
        return res.status(400).send("User not found, Please register first")
    }
    let isValid= await bcrypt.compare(password, user.password)
    if(!isValid){
        return res.status(400).send("Invalid Credentials")
    }

    let token=jwt.sign({email:email, userid:user._id}, "shhh")
    res.cookie("token", token)
    res.send("Logged in successfully")

})

app.get('/logout', (req, res)=>{
    res.cookie("token", "")
    res.redirect('/login')
})

// MIDDLEWARE FOR PROTECTED ROUTES
function isLoggedIn(req, res, next) {
    let token = req.cookies.token;

    if (!token) {
        return res.status(401).send("You must be logged in");
    }

    try {
        let data = jwt.verify(token, "shhh");
        req.user = data; // Attach user data to request
        next(); // Continue to the next middleware/route handler
    } catch (error) {
        return res.status(401).send("Invalid Token. Please log in again.");
    }
}

app.listen(3000)