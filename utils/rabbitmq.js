// authentication microservice rabbitMQ.js
const amqplib = require("amqplib");

const rabbitMQ = {
  sendMessage: async (queue, message) => {
    try {
      const connection = await amqplib.connect(process.env.RABBITMQ_URI);
      const channel = await connection.createChannel();
      await channel.assertQueue(queue, { durable: true });
      channel.sendToQueue(queue, Buffer.from(JSON.stringify(message)));
      console.log(`Message sent to queue: ${queue}`);
      await channel.close();
      await connection.close();
    } catch (error) {
      console.error("RabbitMQ Error:", error);
    }
  },
};

module.exports = rabbitMQ;
