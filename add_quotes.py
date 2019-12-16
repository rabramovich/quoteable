#!/usr/bin/env python3

# Add quotes and sources to quotes.db

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Source, Base, Quote, User

engine = create_engine('sqlite:///quotes.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Anon", email="sample@example.com",
             picture=('\static\quill.jpg'), id=1)
session.add(User1)
session.commit()

# quotes for Ronald Reagan
source1 = Source(user=User1, name="Ronald Reagan")

session.add(source1)
session.commit()

quote1 = Quote(user=User1,
                description="Peace is not absence of conflict, it is the ability to handle conflict by peaceful means.",
                source=source1,)

session.add(quote1)
session.commit()

quote2 = Quote(user=User1,
                description="We must reject the idea that every time a law's broken, society is guilty rather than the lawbreaker. It is time to restore the American precept that each individual is accountable for his actions.",
                source=source1)

session.add(quote2)
session.commit()

quote3 = Quote(user=User1,
                description="The most terrifying words in the English language are: I'm from the government and I'm here to help.",
                source=source1)

session.add(quote3)
session.commit()

quote4 = Quote(user=User1,
                description="We can't help everyone, but everyone can help someone.",
                source=source1)

session.add(quote4)
session.commit()

quote5 = Quote(user=User1,
                description="Trust, but verify.",
                source=source1)

session.add(quote5)
session.commit()



# Quotes for P.T. Barnum
source2 = Source(user=User1, name="P.T. Barnum")

session.add(source2)
session.commit()

quote1 = Quote(user=User1,
                description="Fortune always favors the brave, and never helps a man who does not help himself.",
                source=source2)

session.add(quote1)
session.commit()

quote2 = Quote(user=User1,
                description="Every crowd has a silver lining.",
                source=source2)

session.add(quote2)
session.commit()

quote3 = Quote(user=User1,
                description="There is scarcely anything that drags a person down like debt.",
                source=source2)

session.add(quote3)
session.commit()

quote4 = Quote(user=User1,
                description="Money is in some respects life's fire: it is a very excellent servant, but a terrible master.",
                source=source2)

session.add(quote4)
session.commit()

# Quotes from Albert Einstein
source3 = Source(user=User1, name="Albert Einstein")

session.add(source3)
session.commit()

quote1 = Quote(user=User1,
                description="Learn from yesterday, live for today, hope for tomorrow. The important thing is not to stop questioning.",
                source=source3)

session.add(quote1)
session.commit()

quote2 = Quote(user=User1,
                description="A person who never made a mistake never tried anything new.",
                source=source3)

session.add(quote2)
session.commit()

quote3 = Quote(user=User1,
                description="We cannot solve our problems with the same thinking we used when we created them.",
                source=source3)

session.add(quote3)
session.commit()

quote4 = Quote(user=User1,
                description="If you can't explain it simply, you don't understand it well enough.",
                source=source3)

session.add(quote4)
session.commit()

quote5 = Quote(user=User1,
                description="The only source of knowledge is experience.",
                source=source3)

session.add(quote5)
session.commit()

quote6 = Quote(user=User1,
                description="Any man who can drive safely while kissing a pretty girl is simply not giving the kiss the attention it deserves.",
                source=source3)

session.add(quote6)
session.commit()


print("added quotes to database.")
