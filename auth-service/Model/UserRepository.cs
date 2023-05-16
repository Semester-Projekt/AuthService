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
            // var client = new MongoClient(/*"miljø variabel"*/); // vores mongo conn string

            var client = new MongoClient("mongodb://root:root@localhost:27018/?authSource=admin"); // vores mongo conn string
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
