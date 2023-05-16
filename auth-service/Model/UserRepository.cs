using MongoDB.Driver;
using System.Threading.Tasks;
using Model;
using System;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson;
using System.ComponentModel.DataAnnotations;

namespace Model
{
    public class UserRepository
    {
        private readonly IMongoCollection<User> _user;

        public UserRepository()
        {
            string connectionString = Environment.GetEnvironmentVariable("MONGO_CONNECTION_STRING"); // mongo conn string miljøvariabel
            var client = new MongoClient(connectionString);
            var database = client.GetDatabase("Auctionhouse"); // vores database
            _user = database.GetCollection<User>("User");
        }


        public async Task<User> FindUserByUsernameAndPassword(string userName, string userPassword)
        {
            var filter = Builders<User>.Filter.Eq("UserName", userName) & Builders<User>.Filter.Eq("UserPassword", userPassword);
            return await _user.Find(filter).FirstOrDefaultAsync();
        }

        public void AddNewUser(User user)
        {
            _user.InsertOne(user);
        }
    }
}
