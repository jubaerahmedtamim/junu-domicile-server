const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const app = express();
require('dotenv').config();
const port = process.env.PORT || 5000;


//middlewire
app.use(cors())
app.use(express.json())


const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.yatfw0u.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();

        const userCollection = client.db('JunuDomicileDB').collection('users');


        // jwt related apis
        app.post('/jwt', (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.SECRET_ACCESS_TOKEN, { expiresIn: '1h' });
            res.send({ token });
        })

        // middleware functions
        const verifyToken = (req, res, next) => {
            const bearerToken = req.headers.authorization;
            if (!bearerToken) {
                return res.status(401).send({ message: 'unauthorized access' });
            }
            const token = bearerToken.split(' ')[1];
            jwt.verify(token, process.env.SECRET_ACCESS_TOKEN, (err, decoded) => {
                if (err) {
                    return res.status(401).send({ message: 'unauthorized access' })
                }
                req.decoded = decoded;
                next();
            })
        }

        const verifyAdmin = async (req, res, next) => {
            const userEmail = req.decoded.email;
            const user = await userCollection.findOne({ email: userEmail })
            const isAdmin = user?.role === 'admin';
            if (!isAdmin) {
                return res.status(403).send({ message: 'forbidden access' })
            }
            next();
        }

        // users apis
        app.post('/users', async (req, res) => {
            const userInfo = req.body;
            const query = { email: userInfo.email }
            const isExisting = await userCollection.findOne(query);
            if (isExisting) {
                return res.send({ message: "User already exist.", insertedId: null })
            }
            const result = await userCollection.insertOne(userInfo);
            res.send(result)
        })

        app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
            const result = await userCollection.find().toArray();
            res.send(result);
        })
        // check isAdmin
        app.get('/users/admin', verifyToken, async (req, res) => {
            const email = req.query.email;
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: 'forbidden access.' })
            }
            const user = await userCollection.findOne({ email: email });
            let admin = false;
            if (user) {
                admin = user?.role === 'admin'
            }
            res.send({ admin });
        })
        // check isHost
        app.get('/users/host', verifyToken, async (req, res) => {
            const email = req.query.email;
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: 'forbidden access.' })
            }
            const user = await userCollection.findOne({ email: email })
            let host = false;
            if (user) {
                host = user?.role === 'host';
            }
            res.send({ host });
        })

        app.delete('/users', verifyToken, verifyAdmin, async (req, res) => {
            const result = await userCollection.deleteOne({ _id: new ObjectId(req.query.id) })
            res.send(result)
        })

        app.patch('/users', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.query.id;
            const role = req.body;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $set: {
                    role: role?.userRole,
                }
            }
            const result = await userCollection.updateOne(filter, updatedDoc);
            res.send(result);
        })


        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send('Hello Junu Domicile')
})

app.listen(port, () => {
    console.log(`Junu Domicile is running on port: ${port}`);
})