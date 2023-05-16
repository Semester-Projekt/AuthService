using MongoDB.Driver;
using System.Threading.Tasks;
using System;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson;
using System.ComponentModel.DataAnnotations;

namespace Model
{
	public class User
	{
		[BsonId]
		[BsonRepresentation(BsonType.ObjectId)]
		public string? MongoId { get; set; }

		[BsonElement("UserId")]
		public long UserId { get; set; } // skal måske være en 'int'?

        [BsonElement("UserName")]
        public string UserName { get; set; }

        [BsonElement("UserPassword")]
        public string UserPassword { get; set; }

        [BsonElement("UserEmail")]
        public string? UserEmail { get; set; }

        [BsonElement("UserPhone")]
        public int? UserPhone { get; set; }

        [BsonElement("UserAddress")]
        public string? UserAddress { get; set; }

        public User(string userName, string userPassword, string userEmail, int userPhone, string userAddress)
        {
			this.UserName = userName;
			this.UserPassword = userPassword;
			this.UserEmail = userEmail;
			this.UserPhone = userPhone;
			this.UserAddress = userAddress;
        }

        public User()
		{

		}
	}
}

