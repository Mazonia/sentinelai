FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package.json ./
RUN npm install

# Copy application files
COPY . .

# Expose port
EXPOSE 3000

# Start React app in development mode
CMD ["npm", "start"]
