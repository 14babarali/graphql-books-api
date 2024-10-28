// index.js
const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const mongoose = require('mongoose');


// Add dependencies
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// User model for authentication
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
}));

// Secret key for JWT
const JWT_SECRET = 'your-secret-key';

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/graphql-books', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Connected to MongoDB');
}).catch((error) => {
  console.error('MongoDB connection error:', error);
});

// Mongoose model for Book
const Book = mongoose.model('Book', new mongoose.Schema({
  title: String,
  author: String,
}));

// Express app setup
const app = express();

/// Update schema to support authentication
const schema = buildSchema(`
  type Book {
    id: ID!
    title: String!
    author: String!
  }

  type User {
    id: ID!
    username: String!
  }

  type AuthPayload {
    token: String!
    user: User!
  }

  input BookInput {
    title: String
    author: String
  }

  type Query {
    books(filter: BookInput, skip: Int, limit: Int): [Book]
    book(id: ID!): Book
  }

  type Mutation {
    addBook(title: String!, author: String!): Book
    updateBook(id: ID!, title: String, author: String): Book
    deleteBook(id: ID!): Book
    register(username: String!, password: String!): User
    login(username: String!, password: String!): AuthPayload
  }
`);

// Extend resolvers for authentication
const root = {
  ...root, // include previous resolvers
  register: async ({ username, password }) => {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    return await newUser.save();
  },
  login: async ({ username, password }) => {
    const user = await User.findOne({ username });
    if (!user) throw new Error('User not found');

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) throw new Error('Invalid password');

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
    return { token, user };
  },
};

// Add authentication middleware
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    try {
      const { userId } = jwt.verify(token, JWT_SECRET);
      req.userId = userId;
    } catch (err) {
      console.error('JWT error:', err);
    }
  }
  next();
};

app.use(authenticate);

// Resolvers for MongoDB-based data
const root = {
  books: async ({ filter, skip = 0, limit = 10 }) => {
    let query = {};
    if (filter) {
      query = { ...filter };
    }
    return await Book.find(query).skip(skip).limit(limit);
  },
  book: async ({ id }) => await Book.findById(id),
  addBook: async ({ title, author }) => {
    const newBook = new Book({ title, author });
    return await newBook.save();
  },
  updateBook: async ({ id, title, author }) => {
    return await Book.findByIdAndUpdate(
      id,
      { title, author },
      { new: true }
    );
  },
  deleteBook: async ({ id }) => {
    return await Book.findByIdAndRemove(id);
  },
};

// Set up the GraphQL endpoint
app.use('/graphql', graphqlHTTP({
  schema: schema,
  rootValue: root,
  graphiql: true,
}));

// Start the server
const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}/graphql`);
});
