import amqp from 'amqplib';

let channel: amqp.Channel;

export async function connectRabbitMQ() {
  const conn = await amqp.connect(process.env.RABBITMQ_URL || 'amqp://localhost');
  channel = await conn.createChannel();
  await channel.assertQueue('user.events', { durable: true });
}

export async function publishEvent(queue: string, payload: any) {
  if (!channel) throw new Error("RabbitMQ channel não inicializado");
  channel.sendToQueue(queue, Buffer.from(JSON.stringify(payload)), { persistent: true });
}

export async function consumeEvent(queue: string, callback: (msg: any) => void) {
  if (!channel) throw new Error("RabbitMQ channel não inicializado");
  channel.consume(queue, (msg) => {
    if (msg) {
      const content = JSON.parse(msg.content.toString());
      callback(content);
      channel.ack(msg);
    }
  });
}
