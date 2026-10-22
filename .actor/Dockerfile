# Official pattern: https://docs.apify.com/academy/deploying-your-code/docker-file
# Base image docs: https://docs.apify.com/actors/development/actor-definition/dockerfile
FROM apify/actor-python:3.12

COPY --chown=myuser:myuser requirements.txt ./

RUN echo "Python version:" \
 && python --version \
 && echo "Pip version:" \
 && pip --version \
 && echo "Installing dependencies from requirements.txt:" \
 && pip install -r requirements.txt \
 && echo "All installed Python packages:" \
 && pip freeze

COPY --chown=myuser:myuser . ./

# Matches Apify Python template expectation (python -m src)
CMD ["python", "-m", "src"]
