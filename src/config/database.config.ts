export const databaseConfig = {
  uri: process.env.MONGODB_URI,
  options: {
    // Para conectar con mongo
    connectTimeoutMS: 10000,
    // Para operaciones individuales
    socketTimeoutMS: 45000,
  },
};