//express
const express = require('express')
const app = express()
const port = process.env.PORT || 3000;
app.use(express.json())
var jwt = require('jsonwebtoken')

//mongoDB
const { MongoClient} = require("mongodb");
const uri = "mongodb+srv://fakhrul:1235@clusterfakhrul.bigkwnk.mongodb.net/"
const  client = new MongoClient(uri)

//bcrypt
const bcrypt = require('bcrypt');
const saltRounds = 10;
var hashed;
//token
var token
const privatekey = "PRXWGaming"
var checkpassword;

app.use(express.json());

//login as Owner
app.post( '/loginOwner',async function (req, res) {
  let {idNumber, password} = req.body
  const salt = await bcrypt.genSalt(saltRounds)
  hashed = await bcrypt.hash(password, salt)
  await loginOwner(idNumber, hashed)
})

//login as Security
app.post( '/loginSecurity',async function (req, res) {
  let {idNumber, password} = req.body
  const salt = await bcrypt.genSalt(saltRounds)
  hashed = await bcrypt.hash(password, salt)
  await loginSecurity(idNumber, hashed)
})

//register Owner
app.post('/registerOwner', async function (req, res){
  let header = req.headers.authorization;
  let token = header.split(' ')[1];
  jwt.verify(token, privatekey, async function(err, decoded) {
    console.log(decoded)
    if (await decoded.role == "security"){
      const data = req.body
      res.send(
        registerOwner(
          data.role,
          data.name,
          data.idNumber,
          data.email,
          data.password,
          data.phoneNumber
        )
      )
    }else{
      console.log("You have no access to register an owner!")
    }
})
})

//view visitor 
app.get('/viewVisitor', async (req, res) => {
  await client.connect()
  let header = req.headers.authorization;
  let token = header.split(' ')[1];
  jwt.verify(token, privatekey, async function(err, decoded) {
    console.log(decoded)
    if (await decoded.role == "owner" || await decoded.role == "security"){
      res.send(await client.db("assignmentCondo").collection("visitor").find({}).toArray())
    }
  })
})

app.get('/', (req, res) => {
    res.send("HAHAHAHHAHAHHA")
})

//register visitor
app.post('/registerVisitor', async function (req, res) {
  let header = req.headers.authorization;
  let token = header.split(' ')[1];
  
  jwt.verify(token, privatekey, async function(err, decoded) {
    if (err) {
      console.log("Error decoding token:", err);
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    console.log(decoded);
    
    if (decoded && (decoded.role === "owner" || decoded.role === "security")) {
      const data = req.body;
      
      res.send(
        registerVisitor(
          data.role,
          data.name,
          data.idNumber,
          data.documentType,
          data.gender,
          data.birthDate,
          data.age,
          data.documentExpiry,
          data.company,
          data.TelephoneNumber,
          data.vehicleNumber,
          data.category,
          data.ethnicity,
          data.photoAttributes,
          data.passNumber
        )
      );
    } else {
      console.log("You have no access to register a visitor!");
    }
  });
});



//change pass number
app.post('/changePassNumber', async function (req, res){
  const {savedidNumber, newpassNumber} = req.body
  await changePhoneNumber(savedidNumber, newpassNumber)
  res.send(req.body)
})

//delete visitor
app.post('/deleteVisitor', async function (req, res){
  const {name, idNumber} = req.body
  await deleteVisitor(name, idNumber)
  res.send(req.body)
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

//////////FUNCTION//////////

//CREATE(createListing for owner)
async function createListing1(client, newListing){
  const result = await client.db("assignmentCondo").collection("owner").insertOne(newListing);
  console.log(`New listing created with the following id: ${result.insertedId}`);
}

//CREATE(createListing for visitor)
async function createListing2(client, newListing){
  const result = await client.db("assignmentCondo").collection("visitor").insertOne(newListing);
  console.log(`New listing created with the following id: ${result.insertedId}`);
}

//READ(login as Owner)
async function loginOwner(idNumber, hashed){
  await client.connect()
  const result = await client.db("assignmentCondo").collection("owner").findOne({ idNumber: idNumber });
  const role = await result.role
  if (result) {
    //BCRYPT verify password
    bcrypt.compare(result.password, hashed, function(err, result){
      if(result == true){
        res.send("Access granted. Welcome")
        console.log("Password:", hashed)
        console.log("Role:", role)
        token = jwt.sign({idNumber: idNumber, role: role}, privatekey);
        console.log("Token:", token);
      }else{
        res.send("Wrong password")
      }
    });
  } 
  else {
      res.send("Owner not registered")
  }
}

//READ(login as Security)
async function loginSecurity(idNumber, hashed){
  await client.connect()
  const result = await client.db("assignmentCondo").collection("security").findOne({ idNumber: idNumber });
  const role = await result.role
  if (result) {
    //BCRYPT verify password
    bcrypt.compare(result.password, hashed, function(err, result){
      if(result == true){
        console.log("Access granted. Welcome")
        console.log("Password:", hashed)
        console.log("Role:", role)
        token = jwt.sign({idNumber: idNumber, role: role}, privatekey);
        console.log("Token:", token);
      }else{
        console.log("Wrong password")
      }
    });
  }
  else {
      console.log("Security not registered")
  }
}

//CREATE(register Owner)
async function registerOwner(newrole, newname, newidNumber, newemail, newpassword, newphoneNumber){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("owner").findOne({idNumber: newidNumber})
  if(exist){
    console.log("Owner has already registered")
  }else{
    await createListing1(client,
      {
        role: newrole,
        name: newname,
        idNumber: newidNumber,
        email: newemail,
        password: newpassword,
        phoneNumber: newphoneNumber
      }
    );
    console.log("Owner registered sucessfully")
  }
}

//CREATE(register Visitor)
async function registerVisitor(newrole, newname, newidNumber, newdocumentType, newgender, newbirthDate, 
                        newage, newdocumentExpiry, newcompany, newTelephoneNumber, newvehicleNumber,
                        newcategory, newethnicity, newphotoAttributes, newpassNumber){
  //TODO: Check if username exist
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("visitor").findOne({name: newname})
  if(exist){
      console.log("Visitor has already registered")
  }else{
      await createListing2(client,
        {
          role: newrole,
          name: newname,
          idNumber: newidNumber,
          documentType: newdocumentType,
          gender: newgender,
          birthDate:newbirthDate,
          age: newage,
          documentExpiry: newdocumentExpiry,
          company: newcompany,
          TelephoneNumber: newTelephoneNumber,
          vehicleNumber: newvehicleNumber,
          category: newcategory,
          ethnicity: newethnicity,
          photoAttributes: newphotoAttributes,
          passNumber: newpassNumber 
        }
      );
      console.log("Registered successfully!")
  }
} 

//UPDATE(change pass number)
async function changePhoneNumber(savedidNumber, newpassNumber){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("visitor").findOne({idNumber: savedidNumber})
  if(exist){
    await client.db("assignmentCondo").collection("visitor").updateOne({idNumber: savedidNumber}, {$set: {passNumber: newpassNumber}})
    console.log("Visitor's pass number has changed successfuly.")
  }else{
    console.log("The visitor does not exist.")
  }
}

//DELETE(delete visitor)
async function deleteVisitor(oldname, oldidNumber){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("visitor").findOne({name: oldname})
  if(exist){
    checkidNumber = await exist.idNumber;
    if(oldidNumber == checkidNumber){
      await client.db("assignmentCondo").collection("visitor").deleteOne({name: oldname})
      console.log("Visitor account deleted successfully.")
    }else{
      console.log("ID number is incorrect")
    }
  }else{
    console.log("Visitor does not exist.")
  }
}

//Verify JWT Token
function verifyToken(req, res, next) {
  let header = req.headers.authorization;

  if (!header) {
    return res.status(401).send('Unauthorized');
  }

  let token = header.split(' ')[1];

  jwt.verify(token, 'PRXgaming', function(err, decoded) {
    if (err) {
      console.error(err);
      return res.status(401).send('Invalid token');
    }
    res.user = decoded;
    next();
  });
}
