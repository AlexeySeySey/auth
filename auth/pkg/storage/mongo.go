package storage

import (
	entities "todo_SELF/auth/pkg/entities"
	env "todo_SELF/auth/pkg/env"

	mgo "gopkg.in/mgo.v2"
	bson "gopkg.in/mgo.v2/bson"
)

type Mongo struct {
	mgoSession      *mgo.Session
	usersCollection *mgo.Collection
}

func (m *Mongo) Connect() (*mgo.Session, error) {
	if m.mgoSession == nil {
		var err error
		m.mgoSession, err = mgo.Dial("mongo:" + env.MongoDBPort)
		if err != nil {
			return nil, err
		}
		m.mgoSession.SetMode(mgo.Monotonic, true)
	}
	return m.mgoSession.Clone(), nil
}

func (m *Mongo) GetCollection(mgoSession *mgo.Session) *mgo.Collection {
	m.usersCollection = mgoSession.DB(env.MongoDBDocument).C(env.MongoDBCollection)
	return m.usersCollection
}

func (m *Mongo) Insert(user entities.User) (bson.ObjectId, error) {
	user.Id = bson.NewObjectId()
	if err := m.GetCollection(m.mgoSession).Insert(&user); err != nil {
		return "", err
	}
	return user.Id, nil
}

func (m *Mongo) Search(search bson.M) (entities.User, error) {
	result := entities.User{}
	err := m.GetCollection(m.mgoSession).Find(nil).Select(search).One(&result)
	if err != nil {
		return entities.User{}, err
	}
	return result, nil
}

func (m *Mongo) Update(where bson.M, new bson.M) error {
	if err := m.GetCollection(m.mgoSession).Update(where, bson.M{"$set": new}); err != nil {
		return err
	}
	return nil
}
