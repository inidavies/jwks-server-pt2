const chai = require('chai');
const chaiHttp = require('chai-http');
const server = require('../server.js');
const sqlite3 = require('sqlite3').verbose();

const expect = chai.expect;
chai.use(chaiHttp);

describe('Server', () => {
  before((done) => {
    // Initialize and seed the database before running tests
    db = new sqlite3.Database('./totally_not_my_privateKeys.db');
    db.serialize(() => {
      db.run('DELETE FROM keys'); // Clear the keys table
      done();
    });
  });

  describe('GET /.well-known/jwks.json', () => {
    it('should return a JSON array of valid keys', (done) => {
      chai
        .request(server)
        .get('/.well-known/jwks.json')
        .end((err, res) => {
          expect(res).to.have.status(200);
          expect(res).to.be.json;
          expect(res.body.keys).to.be.an('array');
          expect(res.body.keys).to.have.lengthOf(1);
          done();
        });
    });
  });

  describe('POST /auth', () => {
    it('should return a valid JWT token', (done) => {
      chai
        .request(server)
        .post('/auth')
        .end((err, res) => {
          expect(res).to.have.status(200);
          expect(res.text).to.be.a('string');
          done();
        });
    });

    it('should return an expired JWT token when requested', (done) => {
      chai
        .request(server)
        .post('/auth?expired=true')
        .end((err, res) => {
          expect(res).to.have.status(200);
          expect(res.text).to.be.a('string');
          // validate that the token is expired here
          done();
        });
    });
  });
});

// Clean up after all tests (close the database connection)
after((done) => {
  db.close((err) => {
    if (err) {
      console.error('Error closing the database:', err);
    }
    done();
  });
});
