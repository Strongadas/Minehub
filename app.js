const express = require('express')
const ejs = require('ejs')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const axios = require('axios');
const session = require('express-session')
const passportLocalMongoose = require('passport-local-mongoose')
const passport = require('passport')
const flash = require('connect-flash');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const paypal = require('paypal-rest-sdk')
const escapeHtml = require('escape-html')
const Coinpayments = require('coinpayments');


const PORT = process.env.PORT || 3000

paypal.configure({
  mode: 'sandbox', 
  client_id:"AUG1I7HGk_1rFhkRx4NyZXoSQn_kLkljL4Ixus3X658gaS_NF7FGpoqUamwAXssBhzAOVyZMgvbwbvij" ,
  client_secret: "EKuLVIvlijK8xNm4AzLyJzImJX8lNQ5StH1mkyY-1jcLMaWF3US27XN29uQWMEQec-EtVXf7p_pdpYIB",
})


const client = new Coinpayments({
  key: '68d41e90e4e1fe49c3d527d44167fb0fc808506e5dfa495bc58f53c4fcd44dbb',
  secret: '43e487a17d370a0DD038924b5744c8786ee9Dfc8873c0373b54b0f2bbb8d9C03',
  
});


const app = express()

//mongoose.connect('mongodb://localhost:27017/MineHubDB')
mongoose.connect("mongodb+srv://Anacleto:Strongadas@cluster0.odsr23g.mongodb.net/MineHubDB")

app.use(express.static('public'))
app.set('view engine','ejs')
app.use(bodyParser.urlencoded({ extended: true}))
app.use(bodyParser.json())

app.use(session({
    secret:"LuziaIsalino",
    resave:false,
    saveUninitialized:false
}))

app.use(passport.initialize())
app.use(passport.session())
app.use(flash());

const userSchema = new mongoose.Schema ({
    name:String,
    username: String,
    password: String,
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    balance:{
      type:Number,
      default:0.00000000
    },
    notification:{
      type:Boolean,
      default: true
    },
    wishlistedAddress:{
      type:String,

    },
    hashRates: [
      {
        coin: String,
        hashRate: {
          type: Number,
          default: 0
        },
        timestamp: { type: Date, default: Date.now }
      }
    ],
    despositedAmount:Number,
    
    twoFactorAuthEnabled: {
        type: Boolean,
        default: false // Set to true when user enables 2FA
      },
      twoFactorAuthSecret: {
        type: String // Store the user's 2FA secret key
        // You might want to store this encrypted for security purposes
      },
      twoFactorAuthCompleted: {
        type: Boolean,
        default: false // Set to true when user successfully completes 2FA
      },

})

userSchema.plugin(passportLocalMongoose)



const User = new mongoose.model('User',userSchema)

passport.use(User.createStrategy())
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

//verify if user is Authenticated
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    
    res.redirect('/login');
}

//Get Routes
app.get('/',async(req,res)=>{
    try {
        const cryptoData = await getCryptoPrices();
        
        res.render('home', { cryptoData });
      } catch (error) {
        res.status(500).send('Error fetching data');
      }
})
// Function to fetch cryptocurrency prices
async function getCryptoPrices() {
    const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,tether,binancecoin&vs_currencies=usd');
    return response.data;
  }

  app.get('/login',(req,res)=>{
    const errorMessage = req.flash('error')[0];
    res.render('login',{errorMessage,message:"please verify"})
  })

  app.get('/register',(req,res)=>{
    res.render('register')
  })
  app.get('/forgot-password', (req, res) => {
    res.render('forgot-password'); 
  });
  app.get('/reset/:token', (req, res) => {
    const token = req.params.token;
  
    // Find user by the reset token and check if it's still valid
    User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    }, (err, user) => {
      if (err || !user) {
        return res.render('error', { message: 'Invalid or expired token' });
      }
  
      // Render a form to reset the password
      res.render('reset', { token });
    });
  });

  app.get('/dash', async(req, res, next) => {
    // Check if the user is authenticated
    if (!req.isAuthenticated()) {
      return res.redirect('/login'); // Redirect to login if not authenticated
    }
  
    // If 2FA is enabled and hasn't been completed, redirect to 2FA verification
    if (req.user && req.user.twoFactorAuthEnabled && !req.user.twoFactorAuthCompleted) {
      return res.render('twoFactorVerification',{message:"please verify"}); // Redirect to 2FA verification
    }
    
    try {
      const cryptoData = await getCryptoPrices();
      const user = req.user

      // Simulate a Bitcoin balance (initially 0)
let bitcoinBalance = 0.000000000;

// Function to calculate return every 10 minutes (2.5% per day)
function calculateReturn() {
  // Daily return calculated as 2.5% of the balance
  const dailyReturn = bitcoinBalance + amount/24;

  // Calculating the return every 10 minutes based on the daily return
  const returnEveryTenMinutes = dailyReturn / (24 * 6); // 24 hours * 6 (10-minute intervals)

  return returnEveryTenMinutes;
}

// Simulate receiving returns every 10 minutes
setInterval(() => {
  const returnAmount = calculateReturn();
  bitcoinBalance += returnAmount;

  console.log(`Bitcoin balance increased by ${returnAmount.toFixed(10)} BTC`);
}, 10 * 60 * 1000); // 10 minutes interval

      
      res.render('dash', { cryptoData,user ,bitcoinBalance});
    } catch (error) {
      res.status(500).send('Error fetching data');
    }
 
  });
  
app.get('/transactions',ensureAuthenticated,(req,res)=>{
  const user = req.user
  res.render('transaction-history',{user})
})
app.get('/withdraw',ensureAuthenticated,(req,res)=>{
  const user = req.user
  res.render('withdraw',{user})
})
app.get('/buy-contracts',ensureAuthenticated,(req,res)=>{

  const user = req.user
    
  res.render('buy-contracts',{user})

})
app.get('/settings',ensureAuthenticated,((req,res)=>{
  const user = req.user
  let successMessage ;
  
  if (req.query.success === 'true') {
     successMessage = 'Settings updated successfully';
 }
  res.render('settings',{user,successMessage})
}))
app.get('/support',ensureAuthenticated,(req,res)=>{
  const user = req.user
  res.render('support',{user})
})
app.get('/logout',ensureAuthenticated, (req,res)=>{
  req.logout((err)=>{
    if(err){
        console.log(err)
        res.redirect('/dash')
    }else{
        res.redirect('/')
    }
})
})
app.get('/2fa-verification/:checked', ensureAuthenticated, async (req, res) => {
  const isChecked = req.params.checked === 'true';
  const user = req.user;

  try {
      console.log(isChecked);
      // If 2FA is being enabled
      if (isChecked) {
          const verificationCode = generateVerificationCode(); // Function to generate a verification code
          console.log(verificationCode);
          const userEmail = req.user.username; // Get user's email from the authenticated session

          transporter.sendMail({
              to: userEmail,
              subject: 'Two Factor Verification Code',
              html: `Your 2FA Code is ${verificationCode}.`,
          }, async (err) => {
              if (err) {
                  return res.render('error', { message: 'Error sending reset email' });
              }

              try {
                  await User.findByIdAndUpdate(user._id, {  twoFactorAuthSecret: verificationCode });
                  res.render('2factor', { user, message: 'Verification code sent to email' });
              } catch (err) {
                  console.error(err);
                  res.render('error', { message: 'Error updating user record' });
              }
          });
      }
  } catch (err) {
      console.error(err);
      res.render('error', { message: 'General error' });
  }
});

// Function to generate a random verification code
function generateVerificationCode() {
  const length = 6; // Define the length of the verification code
  const characters = '0123456789'; // Define the characters allowed in the code
  let code = '';

  // Generate a random code using specified characters
  for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * characters.length);
      code += characters.charAt(randomIndex);
  }

  return code; // Return the generated verification code
}

app.get('/payment_error', ensureAuthenticated,(req, res) => {
  const paymentStatus = req.query.status; // Get the payment status query parameter
  console.log("payment ",paymentStatus)
  // Render the 'cancelled' view with the payment status
  res.render('cancelled');
});
app.get('/payment_success', ensureAuthenticated, async (req, res) => {
  const payerId = req.query.PayerID;
  const paymentId = req.query.paymentId;
  const userId = req.user._id;
  const user = req.user

  // Check if payerId, paymentId, and userId are valid
  if (!payerId || !paymentId || !userId) {
      console.error("Invalid parameters.");
      return res.redirect('/payment_cancel');
  }

  const execute_payment_json = {
      "payer_id": payerId,
      "transactions": [{
          "amount": totalAmount
      }]
  };

  console.log("payerId:", payerId);
  console.log("amount:", totalAmount);

  paypal.payment.execute(paymentId, execute_payment_json, async (err, payment) => {
      if (err) {
          console.error(err.response);
          return res.redirect('/payment_error');

      } else {

          console.log("Payment successful");
          console.log(JSON.stringify(payment));

          try {
              // Retrieve the user by their ID
              const user = await User.findById(userId);

              if (!user) {
                  console.error("User not found.");
                  return res.redirect('/payment_error');
              }

            
             // Function to update hash rate for a specific coin
              function updateHashRateForCoin(user, coin, hashrateAmount) {
                const existingCoinIndex = user.hashRates.findIndex(rate => rate.coin === coin);

                if (existingCoinIndex !== -1) {
                  // If the coin exists, update its hash rate by adding the new amount
                  user.hashRates[existingCoinIndex].hashRate += hashrateAmount;
                  user.hashRates[existingCoinIndex].timestamp = new Date();
                } else {
                  // If the coin doesn't exist, create a new entry
                  user.hashRates.push({
                    coin,
                    hashRate: hashrateAmount,
                    timestamp: new Date()
                  });
                }
              }
              updateHashRateForCoin(user, 'BTC', hashrateAmount);
              user.despositedAmount = amount;
              console.log('despositedAmount',despositedAmount)

            // Save the updated user
            user.save((err) => {
              if (err) {
                console.log(err);
              } else {
                console.log("Hash rate updated ", user.hashRates);
              }
            });
              // Send a confirmation email to the user
              const userEmail = req.user.username; // Assuming you have the user's email address
              const subject = 'New payment received from your mining website';
            
              const message = `New Deposit from ${escapeHtml(user.username)},\nAmount: $${amount},\nHashRate: TH${hashrateAmount}\nStatus:Approved`;

              // Create and send the email notification
              const mailOptions = {
                  
                  to: 'strongadas009@gmail.com',
                  subject: subject,
                  text: message,
              };

              const info = await transporter.sendMail(mailOptions);
              console.log('Email notification sent:', info.response);

              const BOT_TOKEN = '6789981476:AAHGPQLaUuvrXr4XCBod9KUmdB87s0eNM20';
              const CHAT_ID = '-1002042570410'; // This can be your group chat ID

              async function sendMessageToGroup(message,amount) {
                try {
                  const response = await axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
                    chat_id: CHAT_ID,
                    text: message,
                  });

                  console.log('Message sent:', response.data);
                } catch (error) {
                  console.error('Error sending message:', error);
                }
              }

              // Usage example
              sendMessageToGroup(message);

              // Render the success page with the updated balance
              res.render("success",{payerId,paymentId,user ,amount, hashrateAmount});
          } catch (error) {
              console.error('Error occurred while processing user or sending email:', error);
              res.redirect('/payment_error');
          }
      }
  });
});



let hashrateAmount;
let amount;
let totalAmount= {}
//Post Route
app.post('/paypalRoute',ensureAuthenticated,(req,res)=>{
  amount = req.body.amount
  hashrateAmount = req.body.hashrateAmount

  amount = parseFloat(amount)
  hashrateAmount = parseInt(hashrateAmount);

  amount = amount + 3
  console.log("hash", hashrateAmount,typeof hashrateAmount)
  console.log('amount',amount, typeof amount)

    // Check if the amount is a valid number
    if (isNaN(amount) || amount <= 0) {
        return res.status(400).send('Invalid amount');
    }
    // Ensure it's a valid number
    if (isNaN(hashrateAmount) || hashrateAmount <= 0) {
      return res.status(400).send('Invalid hashrate amount');
  }

    // Construct the amount object
     totalAmount = {
        currency: 'USD',
        total: amount.toFixed(2) // Format total as a string with two decimal places
    };

    // Construct the payment request
    const paymentRequest = {
        intent: 'sale',
        payer: {
            payment_method: 'paypal'
        },
        redirect_urls: {
            return_url: 'http://localhost:3000/payment_success',
            cancel_url: 'http://localhost:3000/payment_error'
        },
        transactions: [{
            item_list: {
                items: [{
                    name: 'Hashrates',
                    sku: 'Hashrate',
                    price: totalAmount.total,
                    currency: totalAmount.currency,
                    quantity: 1,
                }]
            },
            amount: totalAmount,
            description: 'Buying Hasrates'
        }]
    };

    // Create the payment
    paypal.payment.create(paymentRequest, (error, payment) => {
      console.log('Payment Request:', JSON.stringify(paymentRequest, null, 2));


        if (error) {
            console.error('Error occurred while creating payment:', error);
            return res.status(500).send('Internal Server Error');
        }

        // Redirect to PayPal approval URL
        const approvalUrl = payment.links.find(link => link.rel === 'approval_url');

        if (!approvalUrl) {
            console.error('Approval URL not found in the PayPal response.');
            return res.status(500).send('Internal Server Error');
        }
        console.log('Payment created sucessfully')
        res.redirect(approvalUrl.href);
    });

})

// Inside your route handler
app.post('/usdt', ensureAuthenticated, (req, res) => {
  const amount = parseFloat(req.body.amount);
  const hashrateAmount = parseFloat(req.body.hashrateAmount);
  const user = req.user



  // Set your CoinPayments API credentials
  const merchantId = '8058ea76e492d4ca2f6643d41e234425';
  const publicKey = '68d41e90e4e1fe49c3d527d44167fb0fc808506e5dfa495bc58f53c4fcd44dbb';
  const privateKey = '43e487a17d370a0DD038924b5744c8786ee9Dfc8873c0373b54b0f2bbb8d9C03';
  

  
  
});









app.post('/bitcoin', ensureAuthenticated, async (req, res) => {
   amount = req.body.amount;
   amount = parseFloat(amount)
  hashrateAmount = req.body.hashrateAmount;
  const fromCurrency = 'usdt';
  const toCurrency = 'btc';

  try {
    const apiUrl = `https://api.coincap.io/v2/rates/${fromCurrency}-${toCurrency}`;

    axios.get(apiUrl)
      .then((response) => {
        const exchangeData = response.data.data;
        if (exchangeData) {
          const exchangeRate = exchangeData.rateUsd;
          console.log(`Current exchange rate from ${fromCurrency.toUpperCase()} to ${toCurrency.toUpperCase()}: ${exchangeRate}`);

          // Calculate the equivalent amount in BTC
          const btcEquivalent = amount / exchangeRate;
          console.log(`Equivalent amount in ${toCurrency.toUpperCase()}: ${btcEquivalent}`);

          // Proceed with the rest of your code using the btcEquivalent variable
          // ...

          // For example, send the calculated BTC amount in the response
          res.status(200).json({ btcEquivalent });
        } else {
          console.error('Exchange rate not found for the specified currencies.');
          res.status(500).json({ error: 'Exchange rate not found' });
        }
      })
      .catch((error) => {
        console.error('Error fetching exchange rate:', error);
        res.status(500).json({ error: 'Internal server error' });
      });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }

  });

  app.post('/verifytologin', async (req, res) => {
    try {
      const user = req.user;
      const twoFactorAuthSecret = req.body.twoFactorAuthSecret;
  
      if (twoFactorAuthSecret === user.twoFactorAuthSecret) {
        console.log('2FA Matches', user.twoFactorAuthSecret, 'from body', twoFactorAuthSecret);
        user.twoFactorAuthCompleted = true
        user.save()
        return res.redirect('/dash');
      } else {
        // If the 2FA code entered does not match the stored code
        console.log('2FA does not match');
        return res.redirect('/login?error=invalidCode');
      }
    } catch (err) {
      console.error(err);
      return res.render('error', { message: 'Error during verification process' });
    }
  });
  
  
  


app.post('/register',(req,res)=>{

    const { username, password, name } = req.body;

    const newUser = new User({ username, name });

    
    // Use Passport's register method to add the user to the database
    User.register(newUser, password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect('/');
            
        } else {
            
            passport.authenticate('local')(req, res, () => {
                res.redirect('/dash?welcomeMessage');
                console.log(req.body)
                

            });
        }
    });
})


app.post(
  '/login',
  passport.authenticate('local', {
    failureRedirect: '/login',
    failureFlash: true,
  }),
  async (req, res, next) => {
    try {
      const user = req.user;

      if (user && user.twoFactorAuthEnabled) {
        // Code to handle 2FA verification and sending email
        const verificationCode = generateVerificationCode(); // Function to generate a verification code
        console.log(verificationCode);

        // Generate QR code or render form for 2FA verification
        transporter.sendMail({
          to: user.username,
          subject: 'Two Factor Verification Code',
          html: `Your 2FA Code is ${verificationCode}.`,
        });

        // Save the verification code to the user object
        user.twoFactorAuthSecret = verificationCode;
        await user.save();

        // Render the 2FA verification page or form
        return res.render('twoFactorVerification', { imageUrl: 'URL_TO_QR_CODE' });
      } else {
        // If 2FA is successful or not enabled, proceed to the dashboard
        return res.redirect('/dash');
      }
    } catch (err) {
      console.error(err);
      return res.render('error', { message: 'Error during login process' });
    }
  }
);



app.listen(PORT,()=>{
  console.log(`Server Running on Port ${PORT}`)
})