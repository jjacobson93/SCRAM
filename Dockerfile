FROM swiftdocker/swift

WORKDIR /App/

ADD ./Package.swift /App/
ADD ./Sources /App/Sources

RUN swift package fetch

CMD ["swift", "test"]